from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  mode TEXT,
  repos_scanned INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS repos (
  org TEXT NOT NULL,
  name TEXT NOT NULL,
  url TEXT,
  archived INTEGER,
  fork INTEGER,
  pushed_at TEXT,
  default_branch TEXT,
  has_wiki INTEGER,
  size_kb INTEGER,
  in_inventory INTEGER DEFAULT 1,
  last_commit_at TEXT,
  fetched_at TEXT,
  fetch_error TEXT,
  wiki_fetched INTEGER DEFAULT 0,
  scanned_tips TEXT,
  wiki_scanned_tips TEXT,
  last_scan_run INTEGER,
  scan_error TEXT,
  PRIMARY KEY (org, name)
);
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  org TEXT NOT NULL,
  repo TEXT NOT NULL,
  source TEXT NOT NULL,
  rule TEXT NOT NULL,
  category TEXT NOT NULL,
  masked TEXT NOT NULL,
  value_hash TEXT NOT NULL,
  path TEXT NOT NULL,
  line INTEGER,
  location TEXT,
  commit_sha TEXT NOT NULL,
  author_name TEXT,
  author_email TEXT,
  author_date TEXT,
  github_login TEXT,
  tier TEXT NOT NULL,
  queue TEXT NOT NULL,
  score REAL NOT NULL,
  band TEXT NOT NULL,
  reasons TEXT NOT NULL,
  occurrences INTEGER DEFAULT 1,
  in_head INTEGER,
  first_seen_run INTEGER,
  last_seen_run INTEGER,
  active INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS findings_repo ON findings(org, repo);
CREATE INDEX IF NOT EXISTS findings_value ON findings(value_hash);
CREATE TABLE IF NOT EXISTS run_findings (
  run_id INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  band TEXT,
  in_head INTEGER,
  PRIMARY KEY (run_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS triage (
  fingerprint TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  note TEXT,
  reviewer TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS commit_logins (
  org TEXT, repo TEXT, sha TEXT, login TEXT,
  PRIMARY KEY (org, repo, sha)
);
CREATE TABLE IF NOT EXISTS email_logins (
  email TEXT PRIMARY KEY, login TEXT
);
CREATE TABLE IF NOT EXISTS skipped_docs (
  org TEXT NOT NULL,
  repo TEXT NOT NULL,
  path TEXT NOT NULL,
  blob_sha TEXT NOT NULL,
  reason TEXT NOT NULL,
  size INTEGER,
  commit_sha TEXT,
  PRIMARY KEY (org, repo, blob_sha, path)
);
CREATE TABLE IF NOT EXISTS head_checks (
  org TEXT NOT NULL, repo TEXT NOT NULL, source TEXT NOT NULL, path TEXT NOT NULL, blob_sha TEXT,
  PRIMARY KEY (org, repo, source, path)
);
CREATE TABLE IF NOT EXISTS org_members (
  org TEXT NOT NULL, login TEXT NOT NULL, name TEXT,
  PRIMARY KEY (org, login)
);
CREATE TABLE IF NOT EXISTS repo_teams (
  org TEXT NOT NULL, repo TEXT NOT NULL, team_slug TEXT NOT NULL, team_name TEXT, permission TEXT,
  inherited_from TEXT,
  PRIMARY KEY (org, repo, team_slug)
);
"""

# Columns added after the first release, applied to existing databases
MIGRATIONS = {
    "repos": {"scan_seconds": "REAL", "scan_lines": "INTEGER", "scan_ner_lines": "INTEGER"},
    "email_logins": {"checked_at": "TEXT"},
}

FINDING_COLUMNS = (
    "fingerprint", "org", "repo", "source", "rule", "category", "masked", "value_hash", "path",
    "line", "location", "commit_sha", "author_name", "author_email", "author_date", "tier",
    "queue", "score", "band", "reasons", "occurrences", "in_head",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        for table, cols in MIGRATIONS.items():
            have = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
            for col, kind in cols.items():
                if col not in have:
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {kind}")
        self.db.commit()

    def close(self) -> None:
        self.db.commit()
        self.db.close()

    # repos
    def upsert_inventory(self, org: str, repos: list[dict]) -> None:
        self.db.execute("UPDATE repos SET in_inventory = 0 WHERE org = ?", (org,))
        for r in repos:
            self.db.execute(
                """INSERT INTO repos (org, name, url, archived, fork, pushed_at, default_branch, has_wiki, size_kb, in_inventory)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                   ON CONFLICT(org, name) DO UPDATE SET url=excluded.url, archived=excluded.archived,
                     fork=excluded.fork, pushed_at=excluded.pushed_at, default_branch=excluded.default_branch,
                     has_wiki=excluded.has_wiki, size_kb=excluded.size_kb, in_inventory=1""",
                (org, r["name"], r["html_url"], int(r["archived"]), int(r["fork"]), r.get("pushed_at"),
                 r.get("default_branch"), int(bool(r.get("has_wiki"))), r.get("size")),
            )
        self.db.commit()

    def repos(self, names: list[str] | None = None, limit: int | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM repos WHERE in_inventory = 1"
        params: list = []
        if names:
            sql += f" AND name IN ({','.join('?' * len(names))})"
            params += names
        sql += " ORDER BY org, name"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return self.db.execute(sql, params).fetchall()

    def update_repo(self, org: str, name: str, **fields) -> None:
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(f"UPDATE repos SET {cols} WHERE org = ? AND name = ?", (*fields.values(), org, name))
        self.db.commit()

    # runs
    def start_run(self, mode: str) -> int:
        cur = self.db.execute("INSERT INTO runs (started_at, mode) VALUES (?, ?)", (now(), mode))
        self.db.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int, repos_scanned: int, errors: int) -> None:
        self.db.execute(
            "UPDATE runs SET finished_at = ?, repos_scanned = ?, errors = ? WHERE id = ?",
            (now(), repos_scanned, errors, run_id),
        )
        self.db.execute(
            """INSERT OR REPLACE INTO run_findings (run_id, fingerprint, band, in_head)
               SELECT ?, fingerprint, band, in_head FROM findings WHERE active = 1""",
            (run_id,),
        )
        self.db.commit()

    def latest_runs(self, n: int = 2) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()

    # findings
    def save_repo_findings(self, run_id: int, org: str, repo: str, source: str,
                           findings: list[dict], full: bool) -> None:
        if full:
            self.db.execute(
                "UPDATE findings SET active = 0 WHERE org = ? AND repo = ? AND source = ?", (org, repo, source)
            )
        for f in findings:
            values = {**f, "reasons": json.dumps(f["reasons"])}
            if not full:
                existing = self.db.execute(
                    "SELECT author_date, occurrences FROM findings WHERE fingerprint = ? AND active = 1",
                    (f["fingerprint"],),
                ).fetchone()
                if existing:
                    occ = existing["occurrences"] + f["occurrences"]
                    if (existing["author_date"] or "") <= (f["author_date"] or ""):
                        self.db.execute(
                            "UPDATE findings SET last_seen_run = ?, occurrences = ? WHERE fingerprint = ?",
                            (run_id, occ, f["fingerprint"]),
                        )
                        continue
                    values["occurrences"] = occ
            cols = ", ".join(FINDING_COLUMNS)
            placeholders = ", ".join("?" * len(FINDING_COLUMNS))
            updates = ", ".join(f"{c} = excluded.{c}" for c in FINDING_COLUMNS if c != "fingerprint")
            self.db.execute(
                f"""INSERT INTO findings ({cols}, first_seen_run, last_seen_run, active)
                    VALUES ({placeholders}, ?, ?, 1)
                    ON CONFLICT(fingerprint) DO UPDATE SET {updates}, last_seen_run = excluded.last_seen_run, active = 1""",
                (*[values[c] for c in FINDING_COLUMNS], run_id, run_id),
            )
        self.db.commit()

    def set_in_head(self, org: str, repo: str, source: str, present: set[str],
                    checked: dict[str, str | None] | None = None) -> None:
        """Update default-branch presence for findings in the checked paths (all paths if checked is None)."""
        rows = self.db.execute(
            "SELECT fingerprint, path FROM findings WHERE org = ? AND repo = ? AND source = ? AND active = 1",
            (org, repo, source),
        ).fetchall()
        for row in rows:
            if checked is not None and row["path"] not in checked:
                continue
            self.db.execute(
                "UPDATE findings SET in_head = ? WHERE fingerprint = ?",
                (int(row["fingerprint"] in present), row["fingerprint"]),
            )
        if checked:
            self.db.executemany(
                "INSERT OR REPLACE INTO head_checks (org, repo, source, path, blob_sha) VALUES (?, ?, ?, ?, ?)",
                [(org, repo, source, p, sha) for p, sha in checked.items()],
            )
        self.db.commit()

    def head_checks(self, org: str, repo: str) -> dict[str, dict[str, str | None]]:
        out: dict[str, dict[str, str | None]] = {}
        for r in self.db.execute("SELECT source, path, blob_sha FROM head_checks WHERE org = ? AND repo = ?",
                                 (org, repo)):
            out.setdefault(r["source"], {})[r["path"]] = r["blob_sha"]
        return out

    def save_skipped_docs(self, org: str, repo: str, docs: list[dict], replace: bool) -> None:
        if replace:
            self.db.execute("DELETE FROM skipped_docs WHERE org = ? AND repo = ?", (org, repo))
        self.db.executemany(
            """INSERT OR REPLACE INTO skipped_docs (org, repo, path, blob_sha, reason, size, commit_sha)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(org, repo, d["path"], d["blob_sha"], d["reason"], d["size"], d["commit_sha"]) for d in docs],
        )
        self.db.commit()

    def skipped_docs(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM skipped_docs ORDER BY org, repo, reason, path").fetchall()

    def active_paths(self, org: str, repo: str, source: str) -> dict[str, list[str]]:
        """Paths with active findings and the rules found in each."""
        out: dict[str, list[str]] = {}
        for r in self.db.execute(
            "SELECT DISTINCT path, rule FROM findings WHERE org = ? AND repo = ? AND source = ? AND active = 1",
            (org, repo, source),
        ):
            out.setdefault(r["path"], []).append(r["rule"])
        return out

    # GitHub organisation metadata
    def replace_org_members(self, org: str, members: list[dict]) -> None:
        self.db.execute("DELETE FROM org_members WHERE org = ?", (org,))
        self.db.executemany("INSERT OR REPLACE INTO org_members (org, login, name) VALUES (?, ?, ?)",
                            [(org, m["login"], m.get("name")) for m in members])
        self.db.commit()

    def member_names(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT name FROM org_members WHERE name IS NOT NULL AND name != ''")]

    def replace_repo_teams(self, org: str, rows: list[dict]) -> None:
        self.db.execute("DELETE FROM repo_teams WHERE org = ?", (org,))
        self.db.executemany(
            """INSERT OR REPLACE INTO repo_teams (org, repo, team_slug, team_name, permission, inherited_from)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(org, r["repo"], r["slug"], r["name"], r["permission"], r.get("inherited_from")) for r in rows],
        )
        self.db.commit()

    def repo_teams(self) -> dict[tuple[str, str], list[dict]]:
        out: dict[tuple[str, str], list[dict]] = {}
        for r in self.db.execute("SELECT * FROM repo_teams ORDER BY team_name"):
            out.setdefault((r["org"], r["repo"]), []).append(dict(r))
        return out

    def findings(self, active_only: bool = True) -> list[sqlite3.Row]:
        sql = """SELECT f.*, t.status AS triage_status, t.note AS triage_note, r.url AS repo_url,
                        r.archived, r.last_commit_at, r.pushed_at, r.default_branch
                 FROM findings f
                 LEFT JOIN triage t ON t.fingerprint = f.fingerprint
                 LEFT JOIN repos r ON r.org = f.org AND r.name = f.repo"""
        if active_only:
            sql += " WHERE f.active = 1"
        return self.db.execute(sql).fetchall()

    # triage
    def upsert_triage(self, fingerprint: str, status: str, note: str, reviewer: str) -> None:
        self.db.execute(
            """INSERT INTO triage (fingerprint, status, note, reviewer, updated_at) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(fingerprint) DO UPDATE SET status=excluded.status, note=excluded.note,
                 reviewer=excluded.reviewer, updated_at=excluded.updated_at""",
            (fingerprint, status, note, reviewer, now()),
        )

    def delete_triage(self, fingerprint: str) -> None:
        self.db.execute("DELETE FROM triage WHERE fingerprint = ?", (fingerprint,))
