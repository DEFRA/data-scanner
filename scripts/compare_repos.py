"""Rescan named repos with the current rules (without touching the database) and compare against the last run.

Usage: python scripts/compare_repos.py [--org ORG] repo-a repo-b ...
Only masked values and counts are printed.
"""
from __future__ import annotations

import argparse
import collections
import sqlite3
import time
from pathlib import Path

from pii_scanner.config import load_config
from pii_scanner.scanner import ScanTask, scan_repo

REVIEW = ("High", "Medium", "Low")


def main(org: str, names: list[str]) -> None:
    cfg = load_config(Path("config.toml"))
    db = sqlite3.connect(cfg.db_path)
    for name in names:
        task = ScanTask(org, name, cfg.mirrors_dir / org / f"{name}.git", None, {"code": None, "wiki": None},
                        True, {}, cfg, cfg.hmac_key(), cfg.ner_scope)
        started = time.time()
        res = scan_repo(task)
        new = collections.Counter(f["rule"] for s in res["sources"] for f in s.findings if f["band"] in REVIEW)
        old = collections.Counter(dict(db.execute(
            "SELECT rule, COUNT(*) FROM findings WHERE active = 1 AND org = ? AND repo = ? "
            "AND band IN ('High','Medium','Low') GROUP BY rule", (org, name)).fetchall()))
        print(f"{name}: {time.time() - started:.0f}s error={bool(res['error'])} {res.get('stats')}", flush=True)
        print(f"   before {sum(old.values()):>6} {dict(old.most_common(6))}", flush=True)
        print(f"   after  {sum(new.values()):>6} {dict(new.most_common(6))}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", default="DEFRA")
    parser.add_argument("repos", nargs="+")
    args = parser.parse_args()
    main(args.org, args.repos)
