"""Rescan named repos with the current rules (without touching the database) and compare against the last run.

Usage: python scripts/compare_repos.py repo-a repo-b ...
Only masked values and counts are printed.
"""
from __future__ import annotations

import collections
import sqlite3
import sys
import time
from pathlib import Path

from pii_scanner.config import load_config
from pii_scanner.scanner import ScanTask, scan_repo

REVIEW = ("High", "Medium", "Low")


def main(names: list[str]) -> None:
    cfg = load_config(Path("config.toml"))
    db = sqlite3.connect(cfg.db_path)
    for name in names:
        task = ScanTask("DEFRA", name, cfg.mirrors_dir / "DEFRA" / f"{name}.git", None, {"code": None, "wiki": None},
                        True, {}, cfg, cfg.hmac_key(), cfg.ner_scope)
        started = time.time()
        res = scan_repo(task)
        new = collections.Counter(f["rule"] for s in res["sources"] for f in s.findings if f["band"] in REVIEW)
        old = collections.Counter(dict(db.execute(
            "SELECT rule, COUNT(*) FROM findings WHERE active = 1 AND repo = ? AND band IN ('High','Medium','Low') "
            "GROUP BY rule", (name,)).fetchall()))
        print(f"{name}: {time.time() - started:.0f}s error={bool(res['error'])} {res.get('stats')}", flush=True)
        print(f"   before {sum(old.values()):>6} {dict(old.most_common(6))}", flush=True)
        print(f"   after  {sum(new.values()):>6} {dict(new.most_common(6))}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
