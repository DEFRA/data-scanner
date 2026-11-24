"""GitHub GraphQL access through the gh CLI, with rate limit handling."""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone

from rich.console import Console

RATE_FIELDS = "rateLimit { cost remaining resetAt }"
WRITE_PERMISSIONS = ("ADMIN", "MAINTAIN", "WRITE")


class GitHubError(RuntimeError):
    pass


def graphql(query: str, console: Console | None = None, **variables) -> dict:
    """Run a query; partial results (e.g. some objects NOT_FOUND) are returned rather than raised."""
    args = ["gh", "api", "graphql", "-f", f"query={query}"]
    for k, v in variables.items():
        if v is not None:
            args += ["-f", f"{k}={v}"]
    proc = subprocess.run(args, capture_output=True, text=True)
    try:
        body = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        body = {}
    if not body.get("data"):
        raise GitHubError((proc.stderr or json.dumps(body.get("errors")) or "no response").strip()[:500])
    _respect_rate_limit(body["data"].get("rateLimit"), console)
    return body["data"]


def _respect_rate_limit(rate: dict | None, console: Console | None) -> None:
    if not rate or rate.get("remaining", 1000) > max(50, 2 * rate.get("cost", 1)):
        return
    reset = datetime.fromisoformat(rate["resetAt"].replace("Z", "+00:00"))
    wait = max(0.0, (reset - datetime.now(timezone.utc)).total_seconds()) + 5
    if console:
        console.print(f"[yellow]GitHub GraphQL rate limit nearly used; waiting {int(wait)}s until it resets[/]")
    time.sleep(wait)


def enterprise_orgs(enterprise: str, console: Console | None = None) -> list[str]:
    query = f"""query($enterprise: String!, $cursor: String) {{
      enterprise(slug: $enterprise) {{ organizations(first: 100, after: $cursor) {{
        pageInfo {{ hasNextPage endCursor }} nodes {{ login }} }} }} {RATE_FIELDS} }}"""
    logins, cursor = [], None
    while True:
        ent = graphql(query, console, enterprise=enterprise, cursor=cursor).get("enterprise")
        if not ent:
            raise GitHubError(f"enterprise {enterprise!r} not found or not visible to this token")
        conn = ent["organizations"]
        logins += [n["login"] for n in conn["nodes"] if n]
        if not conn["pageInfo"]["hasNextPage"]:
            return sorted(logins, key=str.lower)
        cursor = conn["pageInfo"]["endCursor"]


def org_members(org: str, console: Console | None = None) -> list[dict]:
    query = f"""query($org: String!, $cursor: String) {{
      organization(login: $org) {{ membersWithRole(first: 100, after: $cursor) {{
        pageInfo {{ hasNextPage endCursor }} nodes {{ login name }} }} }} {RATE_FIELDS} }}"""
    members, cursor = [], None
    while True:
        conn = graphql(query, console, org=org, cursor=cursor)["organization"]["membersWithRole"]
        members += [n for n in conn["nodes"] if n]
        if not conn["pageInfo"]["hasNextPage"]:
            return members
        cursor = conn["pageInfo"]["endCursor"]


def _team_repos(org: str, slug: str, cursor: str | None, console: Console | None) -> list[dict]:
    query = f"""query($org: String!, $slug: String!, $cursor: String) {{
      organization(login: $org) {{ team(slug: $slug) {{ repositories(first: 100, after: $cursor) {{
        pageInfo {{ hasNextPage endCursor }} edges {{ permission node {{ name }} }} }} }} }} {RATE_FIELDS} }}"""
    edges = []
    while cursor:
        conn = graphql(query, console, org=org, slug=slug, cursor=cursor)["organization"]["team"]["repositories"]
        edges += conn["edges"]
        cursor = conn["pageInfo"]["endCursor"] if conn["pageInfo"]["hasNextPage"] else None
    return edges


def team_repo_permissions(org: str, console: Console | None = None) -> list[dict]:
    """Rows of {repo, slug, name, permission, inherited_from} for teams with write, maintain or admin."""
    query = f"""query($org: String!, $cursor: String) {{
      organization(login: $org) {{ teams(first: 25, after: $cursor) {{
        pageInfo {{ hasNextPage endCursor }}
        nodes {{ slug name parentTeam {{ slug }}
          repositories(first: 100) {{ pageInfo {{ hasNextPage endCursor }} edges {{ permission node {{ name }} }} }} }}
      }} }} {RATE_FIELDS} }}"""
    teams: dict[str, dict] = {}
    cursor = None
    while True:
        conn = graphql(query, console, org=org, cursor=cursor)["organization"]["teams"]
        for t in conn["nodes"]:
            repos = t["repositories"]
            edges = repos["edges"]
            if repos["pageInfo"]["hasNextPage"]:
                edges += _team_repos(org, t["slug"], repos["pageInfo"]["endCursor"], console)
            teams[t["slug"]] = {
                "name": t["name"],
                "parent": (t.get("parentTeam") or {}).get("slug"),
                "repos": {e["node"]["name"]: e["permission"] for e in edges if e.get("node")},
            }
        if not conn["pageInfo"]["hasNextPage"]:
            break
        cursor = conn["pageInfo"]["endCursor"]

    rows = []
    for slug, team in teams.items():
        grants = {repo: (perm, None) for repo, perm in team["repos"].items()}
        parent, seen = team["parent"], {slug}
        # Child teams inherit their ancestors' access
        while parent and parent in teams and parent not in seen:
            seen.add(parent)
            for repo, perm in teams[parent]["repos"].items():
                grants.setdefault(repo, (perm, parent))
            parent = teams[parent]["parent"]
        for repo, (perm, inherited) in grants.items():
            if perm in WRITE_PERMISSIONS:
                rows.append({"repo": repo, "slug": slug, "name": team["name"], "permission": perm.lower(),
                             "inherited_from": inherited})
    return rows


def commit_logins(commits: list[tuple[str, str, str]], console: Console | None = None,
                  batch: int = 50) -> dict[tuple[str, str, str], str]:
    """GitHub login of each (org, repo, sha) commit's author; '' where the email has no linked account."""
    out: dict[tuple[str, str, str], str] = {}
    for start in range(0, len(commits), batch):
        chunk = commits[start:start + batch]
        by_repo: dict[tuple[str, str], list[tuple[int, str]]] = {}
        for i, (org, repo, sha) in enumerate(chunk):
            by_repo.setdefault((org, repo), []).append((i, sha))
        parts = []
        for r_i, ((org, repo), shas) in enumerate(by_repo.items()):
            objs = " ".join(
                f"c{i}: object(oid: {json.dumps(sha)}) {{ ... on Commit {{ author {{ user {{ login }} }} }} }}"
                for i, sha in shas
            )
            parts.append(f"r{r_i}: repository(owner: {json.dumps(org)}, name: {json.dumps(repo)}) {{ {objs} }}")
        try:
            data = graphql(f"query {{ {' '.join(parts)} {RATE_FIELDS} }}", console)
        except GitHubError as e:
            if console:
                console.print(f"[yellow]Login lookup batch failed: {e}[/]")
            continue
        for r_i, ((org, repo), shas) in enumerate(by_repo.items()):
            repo_data = data.get(f"r{r_i}") or {}
            for i, sha in shas:
                user = ((repo_data.get(f"c{i}") or {}).get("author") or {}).get("user") or {}
                out[(org, repo, sha)] = user.get("login") or ""
    return out
