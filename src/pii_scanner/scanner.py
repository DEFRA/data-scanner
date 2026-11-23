"""Per-repository scanning: git history, office/PDF blobs, wiki, and default-branch presence."""
from __future__ import annotations

import codecs
import ctypes
import gc
import hashlib
import hmac
import os
import re
import threading
import time
import traceback
import _thread
from collections import defaultdict
from dataclasses import dataclass, field, replace
from fnmatch import fnmatch
from pathlib import Path

from . import blobs, ner
from .config import Config
from .context import PathClassifier, PathInfo, context_signals, file_uses_faker
from .detectors import COOCCURRENCE_RULES, IDENTIFIER_RULES, LINKABLE_RULES, Candidate, detect, mask
from .gitutil import BlobReader, git, git_popen, iter_blobs, read_prefix
from .scoring import Signals, score

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")
COMMIT_MARK = "\x00C\x00"
LOG_FORMAT = "%x00C%x00%H%x00%an%x00%ae%x00%aI"
WINDOW = 3
MAX_PER_PATH_RULE = 100
FAKER_SCAN_BYTES = 2_000_000
MAX_LARGE_VERSIONS = 50  # versions of one large file that are sampled, oldest first
LARGE_PREFIX_BYTES = 4_000_000
NER_CACHE_SIZE = 200_000
# Name detection lines per file version in test and docs files; enough to show real data is present
QUEUE_B_NER_LINES = 200
# Rows sampled from each spreadsheet or large file version in test and docs locations
QUEUE_B_SAMPLE_LINES = 500
# Never diffed or sampled as text
BINARY_EXTENSIONS = frozenset("""
zip gz tgz bz2 xz 7z rar jar war ear whl egg class dll exe so dylib bin o a lib pdb nupkg msi iso img dmg
woff woff2 ttf otf eot ico gif mp3 mp4 mov avi wav ogg webm flac mkv psd ai sketch fig parquet avro orc
shp shx dbf sbn sbx gpkg tif tiff ecw sid mbtiles pbf pyc db sqlite sqlite3 mdb accdb xls doc ppt pptx odt ods
""".split()) | blobs.DOCUMENT_EXTENSIONS | blobs.MEDIA_EXTENSIONS
# Rules whose normalised form is not suitable for masking (lower-cased, or a blob hash)
MASK_FROM_VALUE = frozenset({"person_name", "street_address", "media", "case_text", "special_category"})
# A name may appear alone in a data file; elsewhere it needs a strong identifier on the same line
STRONG_RULES = IDENTIFIER_RULES - {"person_name"}
# In data files, linked data types are personal next to a strong identifier or a name. Elsewhere only a strong
# identifier counts, as name/address pairs in code are mostly licence headers and sample text.
LINK_FOR = {
    "street_address": STRONG_RULES | {"person_name"},
    "postcode": STRONG_RULES | {"person_name"},
    "case_text": STRONG_RULES | {"person_name"},
    "location": STRONG_RULES | {"media"},
}
HONORIFICS = frozenset({"mr", "mrs", "ms", "miss", "mx", "dr", "sir", "dame", "lady", "lord"})

_STAFF: dict[str, frozenset[str]] = {"names": frozenset(), "emails": frozenset()}


def name_key(name: str) -> str:
    tokens = [t for t in re.sub(r"[^\w\s'-]", " ", name.lower()).split() if t not in HONORIFICS]
    return " ".join(tokens)


def set_staff(names, emails) -> None:
    """Org members and commit authors: their names and emails are not reported."""
    _STAFF["names"] = frozenset(k for k in (name_key(n) for n in names) if " " in k)
    _STAFF["emails"] = frozenset(e.lower() for e in emails if e)


@dataclass
class ScanTask:
    org: str
    name: str
    mirror: Path
    wiki_mirror: Path | None
    old_tips: dict[str, list[str] | None]  # source -> tips scanned last time
    full: bool
    known_paths: dict[str, dict[str, list[str]]]  # source -> path -> rules of active findings
    cfg: Config
    key: bytes
    ner_scope: str
    head_checks: dict[str, dict[str, str | None]] = field(default_factory=dict)  # source -> path -> HEAD blob


@dataclass
class SourceResult:
    source: str
    full: bool
    tips: list[str]
    findings: list[dict] = field(default_factory=list)
    head_present: set[str] = field(default_factory=set)
    skipped: bool = False
    skipped_docs: list[dict] = field(default_factory=list)  # documents that could not be scanned
    head_checked: dict[str, str | None] = field(default_factory=dict)  # paths re-checked on HEAD -> blob
    lines: int = 0
    ner_lines: int = 0


@dataclass
class Commit:
    sha: str
    author_name: str
    author_email: str
    author_date: str


@dataclass
class Hit:
    candidate: Candidate
    line: int | None
    location: str | None
    window: list[str]
    cooccurring: int
    line_rules: frozenset[str] = frozenset()


class SourceScanner:
    def __init__(self, task: ScanTask, repo: Path, source: str, classifier: PathClassifier):
        self.task = task
        self.cfg = task.cfg
        self.repo = repo
        self.source = source
        self.wiki = source == "wiki"
        self.classifier = classifier
        self.blobs = BlobReader(repo)
        self.findings: dict[str, dict] = {}
        self.skipped_docs: list[dict] = []
        self.per_path_rule: dict[tuple[str, str], int] = defaultdict(int)
        self.overflow: dict[tuple[str, str], int] = defaultdict(int)
        self.lines_analysed = 0
        self.ner_lines = 0
        # Successive versions of a file repeat most lines, so spaCy results are reused by text
        self.ner_cache: dict[str, tuple[list[Candidate], bool]] = {}

    def close(self) -> None:
        self.blobs.close()

    # Detection --------------------------------------------------------------

    def _ner_wanted(self, path: str, cands: list[Candidate]) -> bool:
        scope = self.task.ner_scope
        if scope == "off":
            return False
        if scope == "all":
            return True
        # Test fixtures and docs: only lines that already hold an email, phone number, NI number etc.
        if self.classifier.classify(path, wiki=self.wiki).queue == "B":
            return any(c.rule in STRONG_RULES for c in cands)
        if cands:
            return True
        return self.source == "document" or self.wiki or self.classifier.ner_eligible(path)

    def _entities(self, texts: list[str]) -> list[tuple[list[Candidate], bool]]:
        todo = [t for t in dict.fromkeys(texts) if t not in self.ner_cache]
        if todo:
            self.ner_lines += len(todo)
            if len(self.ner_cache) > NER_CACHE_SIZE:
                self.ner_cache.clear()
            self.ner_cache.update(zip(todo, ner.entities(self.cfg.ner_model, todo)))
        return [([replace(c, fake=list(c.fake), notes=list(c.notes)) for c in self.ner_cache[t][0]], self.ner_cache[t][1])
                for t in texts]

    def analyse(self, texts: list[str], targets: list[int], path: str, ner_budget: list[int],
                header: str | None = None, header_idx: int | None = None,
                names: bool = True, seen: set[int] | None = None) -> list[tuple[int, Candidate, list[str], int, frozenset[str]]]:
        """Detect on the target lines. Returns (index, candidate, fake hints nearby, co-occurrence count, rules on line).

        Lines whose text is in `seen` are skipped (already checked in an earlier version of the file)."""
        suppressed = self.classifier.suppressed(path, self.wiki)
        run_ner = names and "person_name" not in suppressed
        if self.classifier.classify(path, wiki=self.wiki).queue == "B":
            ner_budget[0] = min(ner_budget[0], QUEUE_B_NER_LINES)
        per_line: dict[int, list[Candidate]] = {}
        line_text: dict[int, str] = {}
        ner_idx, ner_texts = [], []
        max_len = self.cfg.max_line_length
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        for i in targets:
            t = texts[i]
            if not t or len(t) > max_len:
                continue
            if header and i != header_idx:
                t = blobs.labelled(ext, header, t)
            if seen is not None:
                key = hash(t)
                if key in seen:
                    continue
                seen.add(key)
            self.lines_analysed += 1
            ctx = "\n".join(texts[max(0, i - WINDOW): i + WINDOW + 1])
            if header:
                ctx = header + "\n" + ctx
            cands = detect(t, ctx)
            if cands:
                per_line[i] = cands
                line_text[i] = t
            if (run_ner and ner_budget[0] > 0 and ner.CAPITALISED_PAIR.search(t)
                    and self._ner_wanted(path, cands)):
                ner_budget[0] -= 1
                ner_idx.append(i)
                ner_texts.append(t)
                line_text[i] = t
        places: set[int] = set()
        if ner_idx:
            for i, (people, has_place) in zip(ner_idx, self._entities(ner_texts)):
                if people:
                    known = {c.norm for c in per_line.get(i, []) if c.rule == "person_name"}
                    per_line.setdefault(i, []).extend(p for p in people if p.norm not in known)
                if has_place:
                    places.add(i)
        for i in list(per_line):
            per_line[i] = self._filter(per_line[i], line_text[i], suppressed)
            if not per_line[i]:
                del per_line[i]
        identified = {i for i, cands in per_line.items() if any(c.rule in IDENTIFIER_RULES for c in cands)}
        out = []
        for i, cands in per_line.items():
            near_identifier = any(j in identified for j in range(i - WINDOW, i + WINDOW + 1))
            # Special category terms only matter when attached to an identifiable person
            cands = [c for c in cands if c.rule != "special_category" or near_identifier]
            rules = frozenset(c.rule for c in cands)
            window = context_signals("\n".join(texts[max(0, i - WINDOW): i + WINDOW + 1]))
            for c in cands:
                others = rules - {c.rule}
                if c.rule in IDENTIFIER_RULES:
                    n = len(others & COOCCURRENCE_RULES)
                    if i in places and not rules & {"postcode", "street_address", "location"}:
                        n += 1
                else:
                    n = len(others & (IDENTIFIER_RULES | {"special_category"}))
                out.append((i, c, window, n, rules))
        return out

    def _filter(self, cands: list[Candidate], text: str, suppressed: frozenset[str]) -> list[Candidate]:
        """Drop deliberate content: suppressed paths, author credits, internal/project emails and staff."""
        drop = set(suppressed)
        if self.classifier.authorship_line(text):
            drop |= self.classifier.authorship_rules
        out, staff_line = [], False
        for c in cands:
            if c.rule in drop:
                continue
            if c.rule == "email":
                if self.classifier.email_internal(c.norm):
                    staff_line = True
                    continue
                if self.classifier.email_domain_ignored(c.norm) or c.norm in _STAFF["emails"]:
                    continue
            if c.rule == "person_name" and name_key(c.norm) in _STAFF["names"]:
                continue
            out.append(c)
        if staff_line:
            out = [c for c in out if c.rule != "person_name"]
        return out

    def fingerprint(self, c: Candidate, path: str) -> str:
        msg = f"{self.task.org}/{self.task.name}|{self.source}|{c.rule}|{c.norm}|{path}".encode()
        return hmac.new(self.task.key, msg, hashlib.sha256).hexdigest()[:32]

    def value_hash(self, c: Candidate) -> str:
        return hmac.new(self.task.key, f"{c.rule}|{c.norm}".encode(), hashlib.sha256).hexdigest()[:24]

    # Recording --------------------------------------------------------------

    def record_file(self, commit: Commit, path: str, info: PathInfo, hits: list[Hit], faker: bool) -> None:
        distinct: dict[str, set[str]] = defaultdict(set)
        for h in hits:
            distinct[h.candidate.rule].add(h.candidate.norm)
        for h in hits:
            c = h.candidate
            data_context = info.data_like or info.tier in ("data", "wiki") or self.source == "document"
            others = h.line_rules - {c.rule}
            if c.rule == "person_name" and not data_context and not others & STRONG_RULES:
                continue
            links = LINK_FOR.get(c.rule, STRONG_RULES) if data_context else STRONG_RULES | {"media"}
            if c.rule in LINKABLE_RULES and not others & links:
                continue
            matches_author = (
                (c.rule == "email" and c.norm == commit.author_email.lower())
                or (c.rule == "person_name" and c.norm == " ".join(commit.author_name.lower().split()))
            )
            signals = Signals(
                tier=info.tier, data_like=info.data_like, window=h.window, faker_in_file=faker,
                cooccurring=h.cooccurring, bulk=len(distinct[c.rule]), matches_author=matches_author,
            )
            value, band, reasons = score(c, signals)
            self._record(c, path, info, h, commit, value, band, reasons)

    def _record(self, c: Candidate, path: str, info: PathInfo, h: Hit, commit: Commit,
                value: float, band: str, reasons: list[str]) -> None:
        fp = self.fingerprint(c, path)
        existing = self.findings.get(fp)
        if existing is None:
            key = (path, c.rule)
            if self.per_path_rule[key] >= MAX_PER_PATH_RULE:
                self.overflow[key] += 1
                return
            self.per_path_rule[key] += 1
            self.findings[fp] = {
                "fingerprint": fp, "org": self.task.org, "repo": self.task.name, "source": self.source,
                "rule": c.rule, "category": c.category,
                "masked": mask(c.rule, c.value if c.rule in MASK_FROM_VALUE else c.norm),
                "value_hash": self.value_hash(c), "path": path, "line": h.line, "location": h.location,
                "commit_sha": commit.sha, "author_name": commit.author_name, "author_email": commit.author_email,
                "author_date": commit.author_date, "tier": info.tier, "queue": info.queue,
                "score": value, "band": band, "reasons": reasons, "occurrences": 1, "in_head": None,
            }
            return
        existing["occurrences"] += 1
        if commit.author_date < existing["author_date"]:
            existing.update(
                line=h.line, location=h.location, commit_sha=commit.sha, author_name=commit.author_name,
                author_email=commit.author_email, author_date=commit.author_date,
            )
        if value > existing["score"] and band != "Likely fake":
            existing.update(score=value, band=band, reasons=reasons)

    def results(self) -> list[dict]:
        for (path, rule), extra in self.overflow.items():
            group = [f for f in self.findings.values() if f["path"] == path and f["rule"] == rule]
            top = max(group, key=lambda f: f["score"])
            top["reasons"] = [*top["reasons"], f"+{extra} more distinct values of this type in this file not listed"]
        return list(self.findings.values())

    def _faker(self, spec: str) -> bool:
        data = self.blobs.read(spec, FAKER_SCAN_BYTES)
        return bool(data) and file_uses_faker(data.decode("utf-8", errors="replace"))

    # Git history --------------------------------------------------------------

    def scan_history(self, rev_args: list[str], skip_paths: set[str] = frozenset()) -> None:
        excludes = [f":(exclude,glob){g}" for g in self.cfg.exclude_globs]
        # Anything over the command line budget is still skipped by the parser below, just not by git
        excludes += [f":(exclude,literal){p}" for p in sorted(skip_paths)[:2000]]
        proc = git_popen(
            self.repo, "-c", "core.quotePath=false", "log", *rev_args, "-p", "-M", "--no-color",
            "--no-ext-diff", "--diff-merges=off", f"-U{WINDOW}", f"--format={LOG_FORMAT}",
            "--", ".", *excludes,
        )
        commit: Commit | None = None
        path: str | None = None
        in_hunk = False
        hunk: list[tuple[str, str, int]] = []
        file_hits: list[Hit] = []
        ner_budget = [self.cfg.ner_max_lines_per_file]
        header: list[str | None] = [None, None]  # [header text, loaded for path]

        def tabular_header() -> str | None:
            if not path or path.rsplit(".", 1)[-1].lower() not in blobs.TABULAR_EXTENSIONS or not commit:
                return None
            if header[1] != path:
                header[1] = path
                first = next((t for _, t, n in hunk if n == 1), None)
                if first is None:
                    data = self.blobs.read(f"{commit.sha}:{path}", self.cfg.max_document_bytes)
                    first = data.split(b"\n", 1)[0].decode("utf-8", errors="replace").rstrip("\r") if data else None
                header[0] = first
            return header[0]

        def flush_hunk() -> None:
            if not hunk or path is None:
                hunk.clear()
                return
            texts = [t for _, t, _ in hunk]
            targets = [i for i, (k, _, _) in enumerate(hunk) if k == "+"]
            head = tabular_header()
            header_idx = next((i for i, (_, _, n) in enumerate(hunk) if n == 1), None)
            for i, c, window, others, rules in self.analyse(texts, targets, path, ner_budget, head, header_idx):
                file_hits.append(Hit(c, hunk[i][2], None, window, others, rules))
            hunk.clear()

        def flush_file() -> None:
            flush_hunk()
            if file_hits and commit and path:
                info = self.classifier.classify(path, wiki=self.wiki)
                faker = not self.wiki and self._faker(f"{commit.sha}:{path}")
                self.record_file(commit, path, info, file_hits, faker)
            file_hits.clear()
            header[0] = header[1] = None
            ner_budget[0] = self.cfg.ner_max_lines_per_file

        lineno = 0
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\n").rstrip("\r")
            if line.startswith(COMMIT_MARK):
                flush_file()
                parts = line.split("\x00")
                commit = Commit(parts[2], parts[3], parts[4], parts[5])
                path, in_hunk = None, False
            elif line.startswith("diff --git "):
                flush_file()
                path, in_hunk = None, False
            elif not in_hunk:
                if line.startswith("+++ "):
                    target = _unquote(line[4:].rstrip("\t"))
                    path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
                elif line.startswith("@@"):
                    m = HUNK_RE.match(line)
                    lineno = int(m.group(1)) if m else 0
                    in_hunk = True
            elif line.startswith("@@"):
                flush_hunk()
                m = HUNK_RE.match(line)
                lineno = int(m.group(1)) if m else 0
            elif line[:1] in ("+", " "):
                if path is not None and path not in skip_paths:
                    hunk.append((line[0], line[1:], lineno))
                lineno += 1
        flush_file()
        proc.wait()

    # Office / PDF / image blobs ---------------------------------------------

    def analyse_blob(self, path: str, data: bytes, sha: str | None = None, names: bool = True,
                     seen: set[int] | None = None) -> list[Hit] | None:
        """Hits for an office, PDF or image file; None if a document could not be parsed."""
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        sha = sha or blobs.git_blob_sha(data)
        if ext in blobs.MEDIA_EXTENSIONS:
            if "media" in self.classifier.suppressed(path, self.wiki):
                return []
            ev = blobs.inspect_media(path, ext, data)
            if not ev:
                return []
            conf = 0.9 if ev.severity >= 6 else 0.7
            hits = [Hit(Candidate("media", ev.description, sha, ev.severity, conf, notes=ev.notes), None, None, [], 0)]
            if ev.gps:
                lat, lon = ev.gps
                loc = Candidate("location", f"{lat:.5f},{lon:.5f}", f"{lat:.4f},{lon:.4f}", 3.0, 0.8,
                                notes=["GPS position embedded in a photo"])
                hits.append(Hit(loc, None, None, [], 1, frozenset({"media"})))
            return hits
        scanned_pages = 0
        if ext == "pdf":
            try:
                lines, scanned_pages = blobs.extract_pdf(data)
            except Exception:  # corrupt or encrypted
                return None
        else:
            # Spreadsheets are sampled like large text files: real data shows up in the first rows
            lines = blobs.extract_lines(ext, data, max_rows=self._sample_lines(path))
        if lines is None:
            return None
        texts = [t for _, _, t in lines]
        budget = [self.cfg.ner_max_lines_per_file]
        hits = [
            Hit(c, lines[i][1], lines[i][0], window, others, rules)
            for i, c, window, others, rules in self.analyse(texts, list(range(len(texts))), path, budget, names=names,
                                                            seen=seen)
        ]
        if scanned_pages and "media" not in self.classifier.suppressed(path, self.wiki):
            hits.append(Hit(Candidate("media", f"PDF with {scanned_pages} image-only page(s)", sha, 5.0, 0.6,
                                      notes=["scanned document (no text layer)"]), None, None, [], 0))
        return hits

    def _sample_lines(self, path: str) -> int:
        """Rows checked from each version of a spreadsheet or large file; fewer in test and docs locations."""
        sample = self.cfg.large_file_sample_lines
        if self.classifier.classify(path, wiki=self.wiki).queue == "B":
            return min(sample, QUEUE_B_SAMPLE_LINES)
        return sample

    def _oldest_first(self, blob_list: list[tuple[str, int, str]], rev_args: list[str]):
        """Blobs sorted by the date they were first committed, plus that commit for each."""
        commits = introducing_commits(self.repo, rev_args, {b[0] for b in blob_list}) if blob_list else {}
        ordered = sorted(blob_list, key=lambda b: commits[b[0]].author_date if b[0] in commits else "~")
        return ordered, commits

    def scan_documents(self, docs: list[tuple[str, int, str]], rev_args: list[str]) -> None:
        pending: list[tuple[str, str, list[Hit]]] = []
        skipped: list[tuple[str, str, str, int]] = []
        docs, commits = self._oldest_first(docs, rev_args)
        seen: dict[str, set[int]] = defaultdict(set)
        for sha, size, path in docs:
            ext = path.rsplit(".", 1)[-1].lower()
            if ext in blobs.MEDIA_EXTENSIONS and ext not in blobs.EXIF_EXTENSIONS:
                data = b""  # judged on file name only
            elif size > self.cfg.max_document_bytes:
                skipped.append((sha, path, "too large", size))
                continue
            else:
                data = self.blobs.read(sha, self.cfg.max_document_bytes)
                if not data:
                    continue
            hits = self.analyse_blob(path, data, sha, seen=seen[path])
            if hits is None:
                skipped.append((sha, path, "unreadable", size))
            elif hits:
                pending.append((sha, path, hits))
        for sha, path, reason, size in skipped:
            commit = commits.get(sha)
            self.skipped_docs.append({"path": path, "blob_sha": sha, "reason": reason, "size": size,
                                      "commit_sha": commit.sha if commit else None})
        for sha, path, hits in pending:
            commit = commits.get(sha) or self._introducing_commit(sha)
            if commit:
                self.record_file(commit, path, self.classifier.classify(path), hits, faker=False)

    def scan_large(self, large: list[tuple[str, int, str]], rev_args: list[str]) -> None:
        """Sample the start of each version of big text files (datasets, dumps) instead of diffing them."""
        versions: dict[str, int] = defaultdict(int)
        seen: dict[str, set[int]] = defaultdict(set)
        pending: list[tuple[str, str, list[Hit]]] = []
        large, commits = self._oldest_first(large, rev_args)
        for sha, size, path in large:
            if versions[path] >= MAX_LARGE_VERSIONS:
                continue
            versions[path] += 1
            data = read_prefix(self.repo, sha, LARGE_PREFIX_BYTES)
            if b"\x00" in data[:8192]:
                continue
            texts = data.decode("utf-8", errors="replace").splitlines()
            if len(data) < size and texts:
                texts.pop()  # cut mid-line
            sample = self._sample_lines(path)
            texts = texts[:sample]
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            header = texts[0] if texts and ext in blobs.TABULAR_EXTENSIONS else None
            budget = [self.cfg.ner_max_lines_per_file]
            hits = []
            for i, c, window, others, rules in self.analyse(texts, list(range(len(texts))), path, budget, header, 0,
                                                            seen=seen[path]):
                c.notes.append(f"large file: only the first {sample} lines were checked")
                hits.append(Hit(c, i + 1, None, window, others, rules))
            if hits:
                pending.append((sha, path, hits))
        for sha, path, hits in pending:
            commit = commits.get(sha) or self._introducing_commit(sha)
            if commit:
                info = self.classifier.classify(path, wiki=self.wiki)
                self.record_file(commit, path, info, hits, faker=False)

    def _introducing_commit(self, blob_sha: str) -> Commit | None:
        out = git(self.repo, "log", "--all", "--format=%H%x00%an%x00%ae%x00%aI", f"--find-object={blob_sha}")
        commits = [Commit(*line.split("\x00")) for line in out.splitlines() if line.count("\x00") == 3]
        return min(commits, key=lambda c: c.author_date) if commits else None

    # Default branch presence ------------------------------------------------

    def head_fingerprints(self, paths: set[str], new_paths: set[str], name_paths: set[str],
                          previous: dict[str, str | None]) -> tuple[set[str], dict[str, str | None]]:
        """Fingerprints still on the default branch, for paths whose HEAD version changed or that have new findings."""
        present: set[str] = set()
        checked: dict[str, str | None] = {}
        for path in paths:
            oid = self.blobs.oid(f"HEAD:{path}")
            if path not in new_paths and path in previous and previous[path] == oid:
                continue
            checked[path] = oid
            if oid is None:
                continue
            names = path in name_paths
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if self.source == "document":
                media_only = ext in blobs.MEDIA_EXTENSIONS and ext not in blobs.EXIF_EXTENSIONS
                data = b"" if media_only else self.blobs.read(oid, self.cfg.max_document_bytes)
                if data is None:
                    continue
                for h in self.analyse_blob(path, data, oid, names=names) or []:
                    present.add(self.fingerprint(h.candidate, path))
                continue
            data = read_prefix(self.repo, oid, LARGE_PREFIX_BYTES)
            texts = data.decode("utf-8", errors="replace").splitlines()
            if len(data) >= self.cfg.large_file_bytes:
                texts = texts[: self._sample_lines(path)]
            header = texts[0] if texts and ext in blobs.TABULAR_EXTENSIONS else None
            budget = [self.cfg.ner_max_lines_per_file]
            for _, c, _, _, _ in self.analyse(texts, list(range(len(texts))), path, budget, header, 0, names=names):
                present.add(self.fingerprint(c, path))
        return present, checked


def introducing_commits(repo: Path, rev_args: list[str], shas: set[str]) -> dict[str, Commit]:
    """Earliest commit adding each blob, from one pass over the history's file listings."""
    found: dict[str, Commit] = {}
    proc = git_popen(repo, "log", *rev_args, "--raw", "--no-abbrev", "--no-renames", "--diff-merges=off",
                     f"--format={LOG_FORMAT}")
    commit: Commit | None = None
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\n")
        if line.startswith(COMMIT_MARK):
            parts = line.split("\x00")
            commit = Commit(parts[2], parts[3], parts[4], parts[5])
        elif line.startswith(":") and commit:
            meta = line.split("\t", 1)[0].split()
            if len(meta) >= 4 and meta[3] in shas:
                prev = found.get(meta[3])
                if prev is None or commit.author_date < prev.author_date:
                    found[meta[3]] = commit
    proc.wait()
    return found


def _unquote(s: str) -> str:
    """Undo git's C-style quoting of unusual file names."""
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        return s
    raw = codecs.escape_decode(s[1:-1].encode("utf-8"))[0]
    return raw.decode("utf-8", errors="replace")


def _plan(repo: Path, old_tips: list[str] | None, full: bool) -> tuple[list[str] | None, bool, list[str]]:
    """Decide what to scan. Returns (rev args or None if unchanged, is_full, current tips)."""
    tips = sorted(set(git(repo, "for-each-ref", "--format=%(objectname)").split()))
    if full or old_tips is None:
        return ["--all"], True, tips
    if set(old_tips) == set(tips):
        return None, False, tips
    if old_tips:
        unreachable = git(repo, "rev-list", "--count", *old_tips, "--not", "--all", check=False).strip()
        if not unreachable.isdigit() or int(unreachable) > 0:
            return ["--all"], True, tips  # history rewritten or refs deleted
    return ["--all", "--not", *old_tips], False, tips


def _blob_inventory(repo: Path, rev_args: list[str], cfg: Config, with_docs: bool):
    """Documents/images to inspect, and big text files to sample rather than diff, from one object walk."""
    docs: list[tuple[str, int, str]] = []
    large_paths: set[str] = set()

    def excluded(path: str) -> bool:
        return any(fnmatch("/" + path, g) for g in cfg.exclude_globs)

    for sha, size, path in iter_blobs(repo, rev_args):
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        if ext in blobs.DOCUMENT_EXTENSIONS or ext in blobs.MEDIA_EXTENSIONS:
            if with_docs and not excluded(path):
                docs.append((sha, size, path))
        elif size > cfg.large_file_bytes and ext not in BINARY_EXTENSIONS and not excluded(path):
            large_paths.add(path)
    large = [b for b in iter_blobs(repo, rev_args) if b[2] in large_paths] if large_paths else []
    return docs, large_paths, large


def _scan_source(task: ScanTask, repo: Path, source: str, classifier: PathClassifier) -> list[SourceResult]:
    rev_args, is_full, tips = _plan(repo, task.old_tips.get(source), task.full)
    sources = [source] + (["document"] if source == "code" and task.cfg.include_documents else [])
    if rev_args is None:
        return [SourceResult(s, False, tips, skipped=True) for s in sources]
    if not tips:
        return [SourceResult(s, True, tips) for s in sources]
    docs, large_paths, large = _blob_inventory(repo, rev_args, task.cfg, "document" in sources)
    results = []
    for s in sources:
        scanner = SourceScanner(task, repo, s, classifier)
        try:
            if s == "document":
                scanner.scan_documents(docs, rev_args)
            else:
                scanner.scan_history(rev_args, large_paths)
                scanner.scan_large(large, rev_args)
            findings = scanner.results()
            known = task.known_paths.get(s, {})
            new_paths = {f["path"] for f in findings}
            name_paths = {p for p, rules in known.items() if "person_name" in rules}
            name_paths |= {f["path"] for f in findings if f["rule"] == "person_name"}
            previous = {} if is_full else task.head_checks.get(s, {})
            present, checked = scanner.head_fingerprints(set(known) | new_paths, new_paths, name_paths, previous)
        finally:
            scanner.close()
        results.append(SourceResult(s, is_full, tips, findings, present, skipped_docs=scanner.skipped_docs,
                                    head_checked=checked, lines=scanner.lines_analysed,
                                    ner_lines=scanner.ner_lines))
    return results


_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
_mem = {"budget": 0, "start": 0, "active": False, "tripped": False}
_mem_lock = threading.Lock()
_POLL_SECONDS = 0.5


def _rss() -> int:
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * _PAGE
    except (OSError, ValueError, IndexError):
        return 0


def _watch_memory() -> None:
    while True:
        time.sleep(_POLL_SECONDS)
        with _mem_lock:
            if not _mem["active"]:
                continue
            growth = _rss() - _mem["start"]
            if growth > _mem["budget"] * 1.5:
                os._exit(137)  # the abort below did not free enough in time; the runner retries this repo alone
            if growth > _mem["budget"] and not _mem["tripped"]:
                _mem["tripped"] = True
                _thread.interrupt_main()


def init_worker(max_memory_mb: int, staff: tuple[list[str], list[str]] | None = None) -> None:
    """Start a watchdog that aborts a repo scan whose memory growth exceeds the budget, instead of risking an OOM kill.

    Growth is measured from the start of each repo, so the spaCy model's own footprint is not counted."""
    if staff:
        set_staff(*staff)
    if max_memory_mb > 0 and _rss():
        _mem["budget"] = max_memory_mb * 1024 * 1024
        threading.Thread(target=_watch_memory, daemon=True).start()


def _begin_task() -> None:
    with _mem_lock:
        _mem.update(start=_rss(), tripped=False, active=bool(_mem["budget"]))


def _end_task() -> None:
    with _mem_lock:
        _mem["active"] = False
    gc.collect()
    try:
        ctypes.CDLL("libc.so.6").malloc_trim(0)  # hand freed memory back so the next repo starts from a low baseline
    except (OSError, AttributeError):
        pass


def scan_repo(task: ScanTask) -> dict:
    classifier = PathClassifier(task.cfg, task.name)
    result: dict = {"org": task.org, "name": task.name, "sources": [], "error": None, "last_commit_at": None}
    started = time.monotonic()
    _begin_task()
    try:
        result["last_commit_at"] = git(task.mirror, "log", "-1", "--format=%cI", "HEAD", check=False).strip() or None
        result["sources"] += _scan_source(task, task.mirror, "code", classifier)
        if task.wiki_mirror and (task.wiki_mirror / "HEAD").exists():
            result["sources"] += _scan_source(task, task.wiki_mirror, "wiki", classifier)
    except KeyboardInterrupt:
        if not _mem["tripped"]:
            raise
        result["sources"] = []
        result["error"] = (f"MemoryBudgetExceeded: scan used more than {_mem['budget'] >> 20} MB beyond its starting "
                           "memory, likely a very large file; raise [scan] max_memory_mb or exclude the file")
    except Exception as e:  # keep the batch going; error is recorded against the repo
        result["error"] = f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}"
    finally:
        _end_task()
    result["stats"] = {
        "seconds": round(time.monotonic() - started, 1),
        "lines": sum(s.lines for s in result["sources"]),
        "ner_lines": sum(s.ner_lines for s in result["sources"]),
    }
    return result
