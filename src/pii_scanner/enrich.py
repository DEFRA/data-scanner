from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from rich.console import Console

from . import github
from .config import Config
from .store import Store, now

NOREPLY_RE = re.compile(r"^(?:\d+\+)?([A-Za-z0-9-]+)@users\.noreply\.github\.com$", re.I)
RECHECK_UNLINKED_DAYS = 30


def enrich_logins(cfg: Config, store: Store, console: Console) -> int:
    """Map introducing commits to GitHub usernames: one lookup per author email, batched through GraphQL.

    Git author names are not GitHub logins, so GitHub has to resolve the commit."""
    db = store.db
    bands = cfg.enrich_bands
    rows = db.execute(
        f"""SELECT DISTINCT f.org, f.repo, f.commit_sha, lower(f.author_email) AS email, f.source FROM findings f
            LEFT JOIN commit_logins c ON c.org = f.org AND c.repo = f.repo AND c.sha = f.commit_sha
            WHERE f.active = 1 AND c.sha IS NULL AND f.band IN ({','.join('?' * len(bands))})""",
        bands,
    ).fetchall()
    cache = {r["email"]: (r["login"], r["checked_at"])
             for r in db.execute("SELECT email, login, checked_at FROM email_logins")}
    recheck_before = (datetime.now(timezone.utc) - timedelta(days=RECHECK_UNLINKED_DAYS)).isoformat()

    resolved: dict[str, str] = {}
    representative: dict[str, tuple[str, str, str]] = {}
    for r in rows:
        email = r["email"] or ""
        m = NOREPLY_RE.match(email)
        login, checked_at = cache.get(email, (None, None))
        if m:
            resolved[email] = m.group(1)
        elif login:
            resolved[email] = login
        elif login == "" and (checked_at or "") > recheck_before:
            resolved[email] = ""
        elif r["source"] != "wiki":  # wiki commits are not reachable through the repository API
            representative.setdefault(email, (r["org"], r["repo"], r["commit_sha"]))

    if representative:
        console.print(f"Looking up {len(representative)} commit authors via GitHub GraphQL")
        found = github.commit_logins(list(representative.values()), console)
        stamp = now()
        for email, key in representative.items():
            if key in found:
                resolved[email] = found[key]
                db.execute("INSERT OR REPLACE INTO email_logins (email, login, checked_at) VALUES (?, ?, ?)",
                           (email, found[key], stamp))

    for r in rows:
        login = resolved.get(r["email"] or "")
        if login is not None:
            db.execute("INSERT OR REPLACE INTO commit_logins VALUES (?, ?, ?, ?)",
                       (r["org"], r["repo"], r["commit_sha"], login))
    db.execute(
        """UPDATE findings SET github_login = (
             SELECT NULLIF(login, '') FROM commit_logins c
             WHERE c.org = findings.org AND c.repo = findings.repo AND c.sha = findings.commit_sha)
           WHERE active = 1"""
    )
    db.commit()
    return len(representative)


def refresh_teams(cfg: Config, store: Store, console: Console) -> int:
    """Teams with write, maintain or admin access to each repository."""
    total = 0
    for org in cfg.orgs:
        try:
            rows = github.team_repo_permissions(org, console)
        except github.GitHubError as e:
            console.print(f"[yellow]Could not read {org} teams (needs org membership and read:org): {e}[/]")
            continue
        store.replace_repo_teams(org, rows)
        total += len(rows)
    return total


def refresh_members(cfg: Config, store: Store, console: Console) -> int:
    total = 0
    for org in cfg.orgs:
        try:
            members = github.org_members(org, console)
        except github.GitHubError as e:
            console.print(f"[yellow]Could not list {org} members: {e}[/]")
            continue
        store.replace_org_members(org, members)
        total += len(members)
    return total
