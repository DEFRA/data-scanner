"""Build src/pii_scanner/data/given_names.txt from free name datasets.

Sources:
- ONS "Baby names in England and Wales: from 1996" (Open Government Licence v3.0)
- US Social Security Administration top 1000 names per year 1880-2008 (public domain),
  via https://github.com/hadley/data-baby-names

Usage: python scripts/build_given_names.py [--min-count 10]
"""
from __future__ import annotations

import argparse
import csv
import io
import urllib.request
from pathlib import Path

from openpyxl import load_workbook

ONS_URL = (
    "https://www.ons.gov.uk/file?uri=/peoplepopulationandcommunity/birthsdeathsandmarriages/livebirths/"
    "datasets/babynamesinenglandandwalesfrom1996/1996to2025/babynames1996to2025.xlsx"
)
SSA_URL = "https://raw.githubusercontent.com/hadley/data-baby-names/master/baby-names.csv"
OUT = Path(__file__).resolve().parents[1] / "src" / "pii_scanner" / "data" / "given_names.txt"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def ons_names(data: bytes, min_count: int) -> set[str]:
    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    names = set()
    for title in ("Table_1", "Table_2"):
        header = None
        for row in wb[title].iter_rows(values_only=True):
            if header is None:
                if row and row[0] == "Name":
                    header = row
                continue
            if not row or not isinstance(row[0], str):
                continue
            total = sum(v for h, v in zip(header, row) if isinstance(h, str) and h.endswith("Count") and isinstance(v, int))
            if total >= min_count:
                names.add(row[0].strip().lower())
    return names


def ssa_names(data: bytes) -> set[str]:
    reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
    return {row["name"].strip().lower() for row in reader}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-count", type=int, default=10, help="Minimum ONS births across all years")
    args = parser.parse_args()
    names = ons_names(fetch(ONS_URL), args.min_count) | ssa_names(fetch(SSA_URL))
    names = {n for n in names if n.isalpha() and len(n) >= 2}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(sorted(names)) + "\n", encoding="utf-8")
    print(f"Wrote {len(names)} names to {OUT}")


if __name__ == "__main__":
    main()
