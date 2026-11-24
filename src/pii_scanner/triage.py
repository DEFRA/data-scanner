from __future__ import annotations

import csv
import getpass
from pathlib import Path

from .report import _csv_safe, links
from .store import Store

STATUSES = {
    "confirmed": "Real personal data, needs remediation",
    "false_positive": "Not personal data (detector mistake)",
    "fake": "Personal-looking but fake/test data",
    "accepted": "Real but acceptable (e.g. published work contact)",
    "remediated": "Removed and history cleaned",
}
CLEAR = "clear"
FIELDS = ("fingerprint", "status", "note", "band", "score", "queue", "org", "repo", "category", "masked", "path",
          "line", "location", "file_url", "commit_url", "author_name", "github_login", "in_head")


def export_triage(store: Store, path: Path, bands: list[str], include_triaged: bool,
                  orgs: list[str] | None = None) -> int:
    rows = []
    for r in store.findings(orgs=orgs):
        f = dict(r)
        if f["band"] not in bands or (f["triage_status"] and not include_triaged):
            continue
        f["file_url"], f["commit_url"] = links(f)
        f["status"], f["note"] = f["triage_status"] or "", f["triage_note"] or ""
        rows.append({k: _csv_safe(f.get(k)) for k in FIELDS})
    rows.sort(key=lambda r: (-(r["score"] or 0), r["org"], r["repo"]))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def import_triage(store: Store, path: Path, reviewer: str | None = None) -> tuple[int, list[str]]:
    reviewer = reviewer or getpass.getuser()
    updated, problems = 0, []
    with open(path, newline="", encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=2):
            fp = (row.get("fingerprint") or "").strip()
            status = (row.get("status") or "").strip().lower()
            if not fp or not status:
                continue
            if status == CLEAR:
                store.delete_triage(fp)
            elif status in STATUSES:
                store.upsert_triage(fp, status, (row.get("note") or "").strip(), reviewer)
            else:
                problems.append(f"line {i}: unknown status '{status}'")
                continue
            updated += 1
    store.db.commit()
    return updated, problems
