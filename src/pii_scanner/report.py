from __future__ import annotations

import csv
import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .detectors import CATEGORIES
from .scoring import BAND_ORDER
from .store import Store

STATIC_DIR = Path(__file__).parent / "static"
HIDDEN_TRIAGE = ("false_positive", "fake", "accepted", "remediated")
REVIEW_BANDS = ("High", "Medium", "Low")
NO_TEAM = "(no team with write access)"
EXPORT_FIELDS = (
    "priority", "fingerprint", "band", "score", "queue", "tier", "org", "repo", "repo_url", "archived", "last_commit_at",
    "teams", "source", "category", "masked", "path", "line", "location", "file_url", "commit_sha", "commit_url",
    "author_name", "author_email", "github_login", "author_date", "in_head", "occurrences", "reasons",
    "triage_status", "triage_note", "is_new",
)
SUMMARY_FIELDS = ("A High", "A Medium", "A Low", "B High", "B Medium", "B Low", "reviewable", "all findings")


def links(f: dict) -> tuple[str, str]:
    base = f"https://github.com/{f['org']}/{f['repo']}"
    sha = f["commit_sha"]
    if f["source"] == "wiki":
        page = f["path"].rsplit(".", 1)[0]
        return f"{base}/wiki/{quote(page)}/{sha}", f"{base}/wiki/_compare/{sha}"
    file_url = f"{base}/blob/{sha}/{quote(f['path'])}"
    if f["line"] and f["source"] == "code":
        file_url += f"#L{f['line']}"
    return file_url, f"{base}/commit/{sha}"


# How GitHub organisations are written in report text; links and file names keep the real login
ORG_DISPLAY_NAMES = {"defra": "Defra"}


def org_name(org: str) -> str:
    return ORG_DISPLAY_NAMES.get(org.lower(), org)


def repo_slug(org: str, repo: str) -> str:
    return f"{org}__{repo}"


def file_slug(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", key).strip("-")[:120] or "unknown"


def _author(f: dict) -> tuple[str, str]:
    """(grouping key, display label): GitHub login where known, otherwise the commit email."""
    if f.get("github_login"):
        return f"@{f['github_login']}", f"{f['github_login']} (GitHub)"
    email = (f.get("author_email") or "").lower()
    return email or f.get("author_name") or "unknown", f"{f.get('author_name') or ''} <{email}>"


def _load(store: Store, org: str) -> tuple[list[dict], dict]:
    runs = store.latest_runs(2, org)
    prev_ids = store.run_fingerprints(runs[1]["id"], org) if len(runs) == 2 else set()
    teams = store.repo_teams()
    findings = []
    for row in store.findings(orgs=[org]):
        f = dict(row)
        f["reasons"] = json.loads(f["reasons"])
        f["file_url"], f["commit_url"] = links(f)
        f["is_new"] = bool(runs) and len(runs) == 2 and f["fingerprint"] not in prev_ids
        f["hidden"] = f["triage_status"] in HIDDEN_TRIAGE
        f["team_list"] = teams.get((f["org"], f["repo"]), [])
        f["teams"] = ", ".join(t["team_name"] for t in f["team_list"])
        f["author_key"], f["author_label"] = _author(f)
        findings.append(f)
    resolved = 0
    if len(runs) == 2:
        current = {f["fingerprint"] for f in findings}
        resolved = len(prev_ids - current)
    meta = {"runs": [dict(r) for r in runs], "resolved": resolved, "has_previous": len(runs) == 2}
    return findings, meta


def build_report(store: Store, out_dir: Path, orgs: list[str] | None = None) -> Path:
    """One self-contained report per organisation under out_dir/<org>/, plus an index of organisations.

    Without orgs every organisation in the inventory is rebuilt; otherwise only those folders are replaced."""
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals.update(repo_slug=repo_slug, bands=BAND_ORDER, categories=CATEGORIES, export_fields=EXPORT_FIELDS,
                       filter_options=filter_options, head_state=head_state)
    env.filters["org_name"] = org_name

    if orgs is None:
        orgs = store.orgs()
        if out_dir.exists():
            shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for org in orgs:
        _build_org_report(store, env, out_dir / org, org)

    shutil.copytree(STATIC_DIR, out_dir / "assets", dirs_exist_ok=True)
    rows = _org_overview(store)
    for r in rows:
        r["built"] = (out_dir / r["org"] / "index.html").exists()
    html = env.get_template("orgs.html.j2").render(
        meta={"runs": [dict(r) for r in store.latest_runs(1)]}, org=None, root="", nav=None, org_rows=rows)
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    return out_dir / "index.html"


def _org_overview(store: Store) -> list[dict]:
    """Counts only (no finding detail) per organisation, for the top-level index."""
    rows = {org: {"org": org, "repos_total": 0, "repos_with_review": 0, "counts": Counter(), "last_run": None}
            for org in store.orgs()}
    for r in store.db.execute("SELECT org, COUNT(*) FROM repos WHERE in_inventory = 1 GROUP BY org"):
        rows[r[0]]["repos_total"] = r[1]
    hidden, review = ",".join("?" * len(HIDDEN_TRIAGE)), ",".join("?" * len(REVIEW_BANDS))
    visible = f"""FROM findings f LEFT JOIN triage t ON t.fingerprint = f.fingerprint
                  WHERE f.active = 1 AND f.band IN ({review}) AND (t.status IS NULL OR t.status NOT IN ({hidden}))"""
    params = (*REVIEW_BANDS, *HIDDEN_TRIAGE)
    for r in store.db.execute(f"SELECT f.org, f.queue, f.band, COUNT(*) {visible} GROUP BY 1, 2, 3", params):
        if r[0] in rows:
            rows[r[0]]["counts"][(r[1], r[2])] = r[3]
    for r in store.db.execute(f"SELECT f.org, COUNT(DISTINCT f.repo) {visible} GROUP BY 1", params):
        if r[0] in rows:
            rows[r[0]]["repos_with_review"] = r[1]
    for row in rows.values():
        last = store.latest_runs(1, row["org"])
        row["last_run"] = dict(last[0]) if last else None
        row["reviewable"] = sum(row["counts"].values())
    return sorted(rows.values(), key=lambda r: (-r["counts"][("A", "High")], -r["reviewable"], r["org"].lower()))


def _build_org_report(store: Store, env: Environment, out_dir: Path, org: str) -> None:
    findings, meta = _load(store, org)
    repos = [dict(r) for r in store.repos(orgs=[org])]

    if out_dir.exists():
        shutil.rmtree(out_dir)
    for sub in ("repos", "teams", "authors", "exports/repos", "exports/teams", "exports/authors"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)
    shutil.copytree(STATIC_DIR, out_dir / "assets")

    findings.sort(key=lambda f: (BAND_ORDER.index(f["band"]), -f["score"], f["path"], f["line"] or 0))
    by_repo: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        by_repo[(f["org"], f["repo"])].append(f)

    skipped_by_repo: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in store.skipped_docs(org):
        d = dict(row)
        sha = d["commit_sha"]
        d["url"] = f"https://github.com/{d['org']}/{d['repo']}/blob/{sha}/{quote(d['path'])}" if sha else None
        skipped_by_repo[(d["org"], d["repo"])].append(d)

    repo_rows = []
    all_teams = store.repo_teams()
    for r in repos:
        fs = by_repo.get((r["org"], r["name"]), [])
        counts = Counter((f["queue"], f["band"]) for f in fs if not f["hidden"])
        repo_rows.append({**r, "counts": counts, "total": len(fs), "slug": repo_slug(r["org"], r["name"]),
                          "teams": ", ".join(t["team_name"] for t in all_teams.get((r["org"], r["name"]), [])),
                          "skipped": len(skipped_by_repo.get((r["org"], r["name"]), [])),
                          "risk": (counts[("A", "High")], counts[("A", "Medium")], counts[("B", "High")],
                                   counts[("A", "Low")], counts[("B", "Medium")])})
    repo_rows.sort(key=lambda r: r["risk"], reverse=True)
    # Priority: 1 is the repository to investigate first. Every finding list is grouped by repo in this order.
    for i, r in enumerate(repo_rows, 1):
        r["rank"] = i
    rank = {(r["org"], r["name"]): r["rank"] for r in repo_rows}
    for f in findings:
        f["priority"] = rank.get((f["org"], f["repo"]), len(rank) + 1)
        f["export"] = list(_finding_row(f).values())
    # Stable sort, so band and score order is kept within each repo; org/repo keeps unranked (out of inventory) repos together
    findings.sort(key=lambda f: (f["priority"], f["org"], f["repo"]))
    visible = [f for f in findings if not f["hidden"]]
    review = [f for f in visible if f["band"] in REVIEW_BANDS]
    team_rows, team_findings = _group(visible, lambda f: [(t["team_slug"], t["team_name"]) for t in f["team_list"]]
                                      or [("_no-team", NO_TEAM)])
    author_rows, author_findings = _group(visible, lambda f: [(f["author_key"], f["author_label"])])

    summary = {
        "orgs": [org],
        "repos_total": len(repos),
        "repos_with_findings": sum(1 for r in repo_rows if r["total"]),
        "repos_with_review": Counter(
            bool(r["archived"]) for r in repo_rows if any(r["counts"][(q, b)] for q in "AB" for b in REVIEW_BANDS)),
        # Repos with at least one reviewable finding of each band, per queue ("any" = either queue or any band)
        "repos_by_band": Counter(
            (q, b, bool(r["archived"])) for r in repo_rows for q in ("A", "B", "any") for b in (*REVIEW_BANDS, "any")
            if any(r["counts"][(qq, bb)] for qq in ("AB" if q == "any" else q)
                   for bb in (REVIEW_BANDS if b == "any" else (b,)))),
        "scan_errors": [r for r in repos if r["scan_error"] or r["fetch_error"]],
        # Keyed by archived flag as well, so the summary can split active and archived repositories
        "band_queue": Counter((f["queue"], f["band"], bool(f["archived"])) for f in visible),
        "by_category": Counter((f["category"], f["band"], bool(f["archived"])) for f in visible),
        "head": Counter((f["band"], bool(f["in_head"]), bool(f["archived"])) for f in review),
        "new": Counter(f["band"] for f in visible if f["is_new"]),
        "triaged": Counter(f["triage_status"] for f in findings if f["triage_status"]),
        "sources": Counter(f["source"] for f in review),
        "skipped_reasons": Counter(d["reason"] for ds in skipped_by_repo.values() for d in ds),
        "skipped_repos": sorted(
            ({"org": o, "name": n, "slug": repo_slug(o, n), "url": f"https://github.com/{o}/{n}", "count": len(ds)}
             for (o, n), ds in skipped_by_repo.items()),
            key=lambda r: -r["count"]),
    }

    def render(template: str, path: Path, nav: str | None = None, **ctx) -> None:
        html = env.get_template(template).render(meta=meta, summary=summary, nav=nav, org=org, **ctx)
        path.write_text(html, encoding="utf-8")

    render("index.html.j2", out_dir / "index.html", nav="summary", repo_rows=repo_rows, root="")
    for queue, title in (("A", "Queue A: production code, data files and wikis"), ("B", "Queue B: tests, fixtures and docs")):
        render("findings.html.j2", out_dir / f"queue-{queue.lower()}.html", nav=f"queue-{queue.lower()}", root="",
               title=title, findings=[f for f in review if f["queue"] == queue], show_repo=True)
    render("findings.html.j2", out_dir / "new.html", nav="new", root="", title="New since previous run",
           findings=[f for f in visible if f["is_new"]], show_repo=True)
    render("findings.html.j2", out_dir / "triaged.html", nav="triaged", root="", title="Triaged (hidden from queues)",
           findings=[f for f in findings if f["hidden"]], show_repo=True)
    repo_lookup = {(r["org"], r["name"]): r for r in repo_rows}
    for (org, name), fs in by_repo.items():
        render("repo.html.j2", out_dir / "repos" / f"{repo_slug(org, name)}.html", root="../",
               repo=repo_lookup.get((org, name), {"org": org, "name": name}), findings=fs,
               skipped=skipped_by_repo.get((org, name), []))
    for (org, name), ds in skipped_by_repo.items():
        if (org, name) not in by_repo:
            render("repo.html.j2", out_dir / "repos" / f"{repo_slug(org, name)}.html", root="../",
                   repo=repo_lookup.get((org, name), {"org": org, "name": name}), findings=[], skipped=ds)

    render("groups.html.j2", out_dir / "teams.html", nav="teams", root="", title="Findings by team", rows=team_rows,
           kind="teams", csv="exports/by-team.csv",
           intro="Teams with write, maintain or admin access to each repository. A finding counts towards every "
                 "team with access, so totals overlap.")
    render("groups.html.j2", out_dir / "authors.html", nav="authors", root="", title="Findings by author", rows=author_rows,
           kind="authors", csv="exports/by-author.csv",
           intro="Who committed the finding first, by GitHub username where known, otherwise by commit email.")
    for kind, rows, grouped in (("teams", team_rows, team_findings), ("authors", author_rows, author_findings)):
        for g in rows:
            render("group.html.j2", out_dir / kind / f"{g['slug']}.html", nav=kind, root="../", group=g, kind=kind,
                   findings=grouped[g["key"]])

    _export(findings, out_dir)
    _export_groups(out_dir, repo_rows, by_repo, team_rows, team_findings, author_rows, author_findings)


def _group(findings: list[dict], keys) -> tuple[list[dict], dict[str, list[dict]]]:
    """Summary rows and reviewable findings per group (team or author), highest risk first."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    labels: dict[str, str] = {}
    for f in findings:
        if f["band"] not in REVIEW_BANDS:
            continue
        for key, label in keys(f):
            grouped[key].append(f)
            labels[key] = label
    rows = []
    for key, fs in grouped.items():
        counts = Counter((f["queue"], f["band"]) for f in fs)
        rows.append({
            "key": key, "label": labels[key], "slug": file_slug(key), "counts": counts, "total": len(fs),
            "repos": sorted({f["repo"] for f in fs}),
            "categories": ", ".join(c for c, _ in Counter(f["category"] for f in fs).most_common(3)),
            "risk": (counts[("A", "High")], counts[("A", "Medium")], counts[("B", "High")], len(fs)),
        })
    rows.sort(key=lambda r: r["risk"], reverse=True)
    return rows, grouped


def _counts_row(counts: Counter) -> dict:
    row = {f"{q} {b}": counts[(q, b)] for q in "AB" for b in REVIEW_BANDS}
    row["reviewable"] = sum(row.values())
    return row


def _csv_safe(v):
    # Repo content is untrusted: stop spreadsheet apps interpreting cells as formulas
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _write_csv(path: Path, fields, rows) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows({k: _csv_safe(v) for k, v in row.items()} for row in rows)


def _finding_row(f: dict) -> dict:
    return {k: f.get(k) for k in EXPORT_FIELDS} | {"reasons": "; ".join(f["reasons"])}


def _finding_rows(findings: list[dict]) -> list[dict]:
    return [_finding_row(f) for f in findings]


def filter_options(findings: list[dict]) -> dict[str, list[tuple[str, str]]]:
    """(value, label) choices for each finding filter, limited to values present in this table."""
    def present(key, label=str, order=None):
        values = {f[key] for f in findings}
        return [(str(v), label(v)) for v in (sorted(values, key=order) if order else sorted(values))]
    return {
        "band": present("band", order=BAND_ORDER.index),
        "queue": present("queue", lambda v: {"A": "A: production, data, wikis", "B": "B: tests, docs"}[v]),
        "archived": [(v, label) for v, label in (("0", "Active"), ("1", "Archived"))
                     if any(str(int(bool(f["archived"]))) == v for f in findings)],
        "head": [(v, label) for v, label in (("present", "Still present"), ("history", "History only"),
                                             ("unknown", "Unknown")) if any(head_state(f) == v for f in findings)],
        "category": present("category"),
        "tier": present("tier"),
        "source": present("source"),
        "teams": sorted({(t["team_name"], t["team_name"]) for f in findings for t in f["team_list"]}),
        "new": [("1", "New only")] if any(f["is_new"] for f in findings) else [],
    }


def head_state(f: dict) -> str:
    return "present" if f["in_head"] else "history" if f["in_head"] == 0 else "unknown"


def _export(findings: list[dict], out_dir: Path) -> None:
    rows = _finding_rows(findings)
    _write_csv(out_dir / "findings.csv", EXPORT_FIELDS, rows)
    (out_dir / "findings.json").write_text(json.dumps(rows, indent=1, default=str), encoding="utf-8")


def _export_groups(out_dir: Path, repo_rows: list[dict], by_repo: dict, team_rows: list[dict],
                   team_findings: dict, author_rows: list[dict], author_findings: dict) -> None:
    """Summary CSV per dimension, plus one CSV of reviewable findings per repo, team and author to send on."""
    exports = out_dir / "exports"
    repo_fields = ("org", "repo", "url", "archived", "last_commit_at", "pushed_at", "teams", *SUMMARY_FIELDS, "report")
    rows = []
    for r in repo_rows:
        if not r["total"]:
            continue
        rows.append({"org": r["org"], "repo": r["name"], "url": r["url"], "archived": bool(r["archived"]),
                     "last_commit_at": r["last_commit_at"], "pushed_at": r["pushed_at"], "teams": r["teams"],
                     **_counts_row(r["counts"]), "all findings": r["total"], "report": f"repos/{r['slug']}.html"})
        review = [f for f in by_repo[(r["org"], r["name"])] if not f["hidden"] and f["band"] in REVIEW_BANDS]
        if review:
            _write_csv(exports / "repos" / f"{r['slug']}.csv", EXPORT_FIELDS, _finding_rows(review))
    _write_csv(exports / "by-repo.csv", repo_fields, rows)

    for kind, group_rows, grouped in (("teams", team_rows, team_findings), ("authors", author_rows, author_findings)):
        fields = ("name", "repositories", "top types", *SUMMARY_FIELDS[:-1], "report")
        _write_csv(exports / f"by-{kind[:-1]}.csv", fields, [
            {"name": g["label"], "repositories": ", ".join(g["repos"]), "top types": g["categories"],
             **_counts_row(g["counts"]), "report": f"{kind}/{g['slug']}.html"}
            for g in group_rows
        ])
        for g in group_rows:
            _write_csv(exports / kind / f"{g['slug']}.csv", EXPORT_FIELDS, _finding_rows(grouped[g["key"]]))
