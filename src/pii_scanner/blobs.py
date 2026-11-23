"""Text extraction and media inspection for binary files found in git history."""
from __future__ import annotations

import csv
import hashlib
import io
import logging
import re
import warnings
from dataclasses import dataclass, field

DOCUMENT_EXTENSIONS = frozenset({"xlsx", "xlsm", "docx", "pdf"})
MEDIA_EXTENSIONS = frozenset({"jpg", "jpeg", "png", "tif", "tiff", "heic", "heif", "bmp", "webp"})
# Only these can carry camera EXIF, so only these blobs are read; others are judged by file name
EXIF_EXTENSIONS = frozenset({"jpg", "jpeg", "tif", "tiff", "webp"})
TABULAR_EXTENSIONS = frozenset({"csv", "tsv"})

logging.getLogger("pypdf").setLevel(logging.ERROR)

ID_DOC_NAME = re.compile(
    r"signature|signed|passport|driving[ _-]?licen[cs]e|licen[cs]e[ _-]?(photo|scan)|id[ _-]?card|identity|"
    r"proof[ _-]?of[ _-]?(id|address)|utility[ _-]?bill|bank[ _-]?statement|birth[ _-]?certificate",
    re.I,
)
PHOTO_NAME = re.compile(
    r"(^|/)(IMG|DSC|DSCN|PXL|MVIMG)_?\d|WhatsApp Image|selfie|headshot|portrait|(^|[/_ -])scan(ned)?([_ -]?\d|\.)", re.I
)


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def label_row(header: list[str], cells: list[str]) -> str:
    """'h1: v1, h2: v2' so column names act as keywords for the row's values."""
    return ", ".join(f"{h}: {c}" if h else c for h, c in zip(header, cells) if c)


def split_row(line: str, delimiter: str) -> list[str]:
    try:
        return next(csv.reader([line], delimiter=delimiter))
    except (csv.Error, StopIteration):
        return []


def labelled(ext: str, header: str, line: str) -> str:
    delim = "\t" if ext == "tsv" else max((",", ";", "\t", "|"), key=header.count)
    cols, cells = split_row(header, delim), split_row(line, delim)
    if len(cols) < 2 or len(cells) != len(cols):
        return line
    return label_row([c.strip() for c in cols], [c.strip() for c in cells])


def extract_lines(ext: str, data: bytes, max_rows: int = 200_000) -> list[tuple[str, int | None, str]] | None:
    """(location label, line number or None, text) tuples; None if the file could not be parsed."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # openpyxl warns about Excel extensions it ignores; values still load
            if ext in ("xlsx", "xlsm"):
                return _xlsx(data, max_rows)
            if ext == "docx":
                return _docx(data)
            if ext == "pdf":
                return _pdf(data)
    except Exception:  # corrupt, encrypted or password protected files are common in history
        return None
    return []


def _xlsx(data: bytes, max_rows: int) -> list[tuple[str, int | None, str]]:
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    out = []
    for ws in wb.worksheets:
        header: list[str] | None = None
        for i, row in enumerate(ws.iter_rows(values_only=True), start=1):
            if i > max_rows:
                break
            cells = ["" if v is None else str(v).strip() for v in row]
            if not any(cells):
                continue
            text = ", ".join(c for c in cells if c) if header is None else label_row(header, cells)
            header = header or cells
            out.append((f"{ws.title}!row {i}", i, text))
    wb.close()
    return out


def _docx(data: bytes) -> list[tuple[str, int | None, str]]:
    import docx

    doc = docx.Document(io.BytesIO(data))
    out = []
    for i, p in enumerate(doc.paragraphs, start=1):
        if p.text.strip():
            out.append((f"paragraph {i}", None, p.text))
    for t_i, table in enumerate(doc.tables, start=1):
        header: list[str] | None = None
        for r_i, row in enumerate(table.rows, start=1):
            cells = [c.text.strip() for c in row.cells]
            if not any(cells):
                continue
            text = ", ".join(c for c in cells if c) if header is None else label_row(header, cells)
            header = header or cells
            out.append((f"table {t_i} row {r_i}", None, text))
    return out


def _pdf(data: bytes) -> list[tuple[str, int | None, str]]:
    return extract_pdf(data)[0]


def extract_pdf(data: bytes, max_scan_pages: int = 50, max_pages: int = 300) -> tuple[list[tuple[str, int | None, str]], int]:
    """Text lines plus the number of image-only pages (typical of scans), from a single parse."""
    from pypdf import PdfReader

    out, scanned = [], 0
    for p_i, page in enumerate(PdfReader(io.BytesIO(data)).pages[:max_pages], start=1):
        text = page.extract_text() or ""
        if not text.strip() and p_i <= max_scan_pages:
            resources = page.get("/Resources") or {}
            if hasattr(resources, "get") and resources.get("/XObject"):
                scanned += 1
        for line in text.splitlines():
            if line.strip():
                out.append((f"page {p_i}", None, line))
    return out, scanned


def scanned_pdf_pages(data: bytes, max_pages: int = 50) -> int:
    """Pages that contain images but no text layer, typical of scanned documents."""
    try:
        return extract_pdf(data, max_pages)[1]
    except Exception:
        return 0


@dataclass
class MediaEvidence:
    description: str
    severity: float
    notes: list[str] = field(default_factory=list)
    gps: tuple[float, float] | None = None


def _dms(values, ref) -> float | None:
    try:
        d, m, s = (float(v) for v in values)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    dec = d + m / 60 + s / 3600
    return -dec if ref in ("S", "W") else dec


def inspect_media(path: str, ext: str, data: bytes) -> MediaEvidence | None:
    name = path.rsplit("/", 1)[-1]
    notes: list[str] = []
    severity = 0.0
    gps = None
    if ID_DOC_NAME.search(name):
        notes.append("file name suggests an identity document, signature or statement")
        severity = max(severity, 6.0)
    if PHOTO_NAME.search(name):
        notes.append("camera or scanner style file name")
        severity = max(severity, 3.0)
    if ext in ("heic", "heif"):
        notes.append("phone camera format")
        severity = max(severity, 3.0)
    elif ext in EXIF_EXTENSIONS and data:
        try:
            from PIL import Image

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                exif = Image.open(io.BytesIO(data)).getexif()
            camera = " ".join(str(exif.get(t, "")).strip("\x00 ") for t in (271, 272)).strip()
            if camera:
                notes.append(f"camera EXIF ({camera[:40]})")
                severity = max(severity, 2.5)
            gps_ifd = exif.get_ifd(0x8825)
            if gps_ifd and 2 in gps_ifd and 4 in gps_ifd:
                lat, lon = _dms(gps_ifd[2], gps_ifd.get(1)), _dms(gps_ifd[4], gps_ifd.get(3))
                if lat is not None and lon is not None and (lat, lon) != (0.0, 0.0):
                    gps = (lat, lon)
                    notes.append("GPS position in EXIF")
                    severity = max(severity, 3.5)
        except Exception:  # not an image Pillow understands, or no EXIF
            pass
    if not notes:
        return None
    return MediaEvidence(f"{ext.upper()} image: " + "; ".join(notes), severity, notes, gps)
