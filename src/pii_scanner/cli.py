from __future__ import annotations

import json
import re
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

from .config import Config, load_config
from .enrich import enrich_logins, refresh_members, refresh_teams
from .fetch import fetch_repo, mirror_path
from .github import GitHubError, enterprise_orgs
from .gitutil import git
from .inventory import refresh_inventory
from .report import build_report
from .runner import auto_memory_limit_mb, scan_results
from .scanner import ScanTask
from .store import Store, now
from .triage import STATUSES, export_triage, import_triage

app = typer.Typer(no_args_is_help=True, help="Scan GitHub organisations' public repositories for leaked personal data.")
triage_app = typer.Typer(no_args_is_help=True, help="Export findings for review and import decisions.")
app.add_typer(triage_app, name="triage")
console = Console()

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", help="Path to config.toml")]
ReposOpt = Annotated[Optional[str], typer.Option(help="Comma separated repo names to limit to")]
LimitOpt = Annotated[Optional[int], typer.Option(help="Only process the first N repos (alphabetical)")]
OrgOpt = Annotated[Optional[str], typer.Option("--org", help="Comma separated organisations (overrides config orgs)")]
ORG_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")


def _setup(config: Path, org: str | None = None) -> tuple[Config, Store]:
    cfg = load_config(config)
    if org is not None:
        cfg.orgs = _orgs(org)
    return cfg, Store(cfg.db_path)


def _orgs(value: str) -> list[str]:
    orgs = [o.strip() for o in value.split(",") if o.strip()]
    # Logins become report folder names, so reject anything that is not a GitHub login
    bad = [o for o in orgs if not ORG_LOGIN.match(o)]
    if bad or not orgs:
        raise typer.BadParameter(f"not a GitHub organisation login: {', '.join(bad) or value!r}", param_hint="--org")
    return orgs


def _names(repos: str | None) -> list[str] | None:
    return [r.strip() for r in repos.split(",") if r.strip()] if repos else None


def _progress() -> Progress:
    return Progress(TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                    TextColumn("{task.fields[current]}"), console=console)


def _resolve_ner(cfg: Config, scope: str) -> str:
    if scope == "off":
        return scope
    try:
        import spacy.util
    except ImportError:
        console.print("[yellow]spaCy not installed, name detection disabled (pip install -e '.[ner]')[/]")
        return "off"
    if not spacy.util.is_package(cfg.ner_model):
        console.print(f"[yellow]spaCy model {cfg.ner_model} missing, name detection disabled "
                      f"(python -m spacy download {cfg.ner_model})[/]")
        return "off"
    return scope


def do_inventory(cfg: Config, store: Store) -> None:
    counts, errors = refresh_inventory(cfg, store)
    for org, n in counts.items():
        console.print(f"{org}: {n} public repositories in scope")
    for org, error in errors.items():
        console.print(f"[yellow]{org}: could not list repositories, kept the previous list ({error})[/]")
    if errors:
        console.print("[yellow]Run `pii-scan inventory` again when the connection is back[/]")
    if cfg.ignore_staff:
        console.print(f"{refresh_members(cfg, store, console)} organisation members recorded as staff")


def do_teams(cfg: Config, store: Store) -> None:
    console.print(f"{refresh_teams(cfg, store, console)} team permissions (write or above) recorded")


def _commit_authors(cfg: Config, repos) -> tuple[list[str], list[str]]:
    """Names and emails of everyone who has committed to the scanned repos, treated as staff."""
    def authors(path: Path) -> list[str]:
        if not (path / "HEAD").exists():
            return []
        return git(path, "log", "--all", "--format=%an%x00%ae", check=False).splitlines()

    paths = [mirror_path(cfg.mirrors_dir, r["org"], r["name"]) for r in repos]
    paths += [mirror_path(cfg.mirrors_dir, r["org"], r["name"], wiki=True) for r in repos]
    names, emails = set(), set()
    with ThreadPoolExecutor(cfg.fetch_workers) as pool:
        for lines in pool.map(authors, paths):
            for line in lines:
                name, _, email = line.partition("\x00")
                names.add(name)
                emails.add(email.lower())
    return sorted(names), sorted(emails)


def do_fetch(cfg: Config, store: Store, names: list[str] | None, limit: int | None) -> None:
    repos = store.repos(names, limit, cfg.orgs)
    if not repos:
        console.print("[yellow]No repositories in inventory; run `pii-scan inventory` first[/]")
        return
    errors = 0
    with _progress() as progress, ThreadPoolExecutor(cfg.fetch_workers) as pool:
        bar = progress.add_task("Fetching", total=len(repos), current="")
        futures = {
            pool.submit(fetch_repo, cfg.mirrors_dir, r["org"], r["name"], r["default_branch"],
                        bool(r["has_wiki"]), cfg.include_wikis): r
            for r in repos
        }
        for fut in as_completed(futures):
            r = futures[fut]
            error, wiki_ok = fut.result()
            errors += bool(error)
            store.update_repo(r["org"], r["name"], fetched_at=now(), fetch_error=error, wiki_fetched=int(wiki_ok))
            progress.update(bar, advance=1, current=r["name"])
    console.print(f"Fetched {len(repos)} repositories ({errors} errors)")


def do_scan(cfg: Config, store: Store, names: list[str] | None, limit: int | None, full: bool,
            ner_scope: str | None) -> int:
    scope = _resolve_ner(cfg, ner_scope or cfg.ner_scope)
    key = cfg.hmac_key()
    repos = [r for r in store.repos(names, limit, cfg.orgs)
             if (mirror_path(cfg.mirrors_dir, r["org"], r["name"]) / "HEAD").exists()]
    if not repos:
        console.print("[yellow]No fetched repositories to scan; run `pii-scan fetch` first[/]")
        raise typer.Exit(1)
    run_id = store.start_run("full" if full else "incremental", sorted({r["org"] for r in repos}))
    tasks = []
    # Biggest first, so one huge repo does not start last and stretch the run
    for r in sorted(repos, key=lambda r: -(r["size_kb"] or 0)):
        old = {
            "code": json.loads(r["scanned_tips"]) if r["scanned_tips"] else None,
            "wiki": json.loads(r["wiki_scanned_tips"]) if r["wiki_scanned_tips"] else None,
        }
        known = {s: store.active_paths(r["org"], r["name"], s) for s in ("code", "document", "wiki")}
        wiki = mirror_path(cfg.mirrors_dir, r["org"], r["name"], wiki=True) if cfg.include_wikis else None
        tasks.append(ScanTask(r["org"], r["name"], mirror_path(cfg.mirrors_dir, r["org"], r["name"]), wiki,
                              old, full, known, cfg, key, scope, store.head_checks(r["org"], r["name"])))
    staff = None
    if cfg.ignore_staff:
        # Every organisation in the database, so staff of any enterprise organisation count as staff
        names, emails = _commit_authors(cfg, store.repos())
        staff = (names + store.member_names(), emails)
        console.print(f"Ignoring {len(staff[0])} staff names and {len(emails)} staff emails")
    errors = 0
    mem = cfg.max_memory_mb or auto_memory_limit_mb(cfg.scan_workers)
    console.print(f"Run {run_id}: scanning {len(tasks)} repositories ({'full' if full else 'incremental'}, "
                  f"name detection: {scope}, {cfg.scan_workers} workers, "
                  f"{str(mem) + ' MB' if mem else 'no'} memory budget per repo)")
    timings = []
    with _progress() as progress:
        bar = progress.add_task("Scanning", total=len(tasks), current="")
        for res in scan_results(tasks, cfg.scan_workers, mem, staff=staff):
            _persist(store, run_id, res)
            if res["error"]:
                errors += 1
                console.print(f"[red]{res['name']}: {res['error'].splitlines()[0]}[/]")
            if res.get("stats"):
                timings.append((res["stats"]["seconds"], res["name"], res["stats"]))
            progress.update(bar, advance=1, current=res["name"])
    store.finish_run(run_id, len(tasks), errors)
    if timings:
        console.print("Slowest repositories:")
        for seconds, name, stats in sorted(timings, reverse=True)[:10]:
            console.print(f"  {seconds:>7.1f}s  {name}  ({stats['lines']:,} lines checked, "
                          f"{stats['ner_lines']:,} through name detection)")
    skipped = store.db.execute("SELECT reason, COUNT(*) FROM skipped_docs GROUP BY reason").fetchall()
    if skipped:
        detail = ", ".join(f"{n} {reason}" for reason, n in skipped)
        console.print(f"[yellow]Documents not scanned: {detail} (listed in the report)[/]")
    console.print(f"Run {run_id} complete ({errors} errors)")
    return run_id


def _persist(store: Store, run_id: int, res: dict) -> None:
    org, name = res["org"], res["name"]
    fields = {"scan_error": res["error"], "last_scan_run": run_id}
    if res["last_commit_at"]:
        fields["last_commit_at"] = res["last_commit_at"]
    if res.get("stats"):
        fields.update(scan_seconds=res["stats"]["seconds"], scan_lines=res["stats"]["lines"],
                      scan_ner_lines=res["stats"]["ner_lines"])
    if not res["error"]:
        for sr in res["sources"]:
            if sr.source != "document":
                fields["wiki_scanned_tips" if sr.source == "wiki" else "scanned_tips"] = json.dumps(sr.tips)
            if sr.skipped:
                continue
            store.save_repo_findings(run_id, org, name, sr.source, sr.findings, sr.full)
            store.set_in_head(org, name, sr.source, sr.head_present, sr.head_checked)
            if sr.source == "document":
                store.save_skipped_docs(org, name, sr.skipped_docs, replace=sr.full)
    store.update_repo(org, name, **fields)


def do_report(cfg: Config, store: Store, orgs: list[str] | None = None) -> Path:
    index = build_report(store, cfg.reports_dir, orgs)
    console.print(f"Report written to {index}")
    return index


@app.command()
def inventory(config: ConfigOpt = Path("config.toml"), org: OrgOpt = None) -> None:
    """List each organisation's public, non-fork repositories via gh."""
    cfg, store = _setup(config, org)
    do_inventory(cfg, store)
    store.close()


@app.command()
def fetch(config: ConfigOpt = Path("config.toml"), repos: ReposOpt = None, limit: LimitOpt = None,
          org: OrgOpt = None) -> None:
    """Create or update local bare mirrors (branches, tags, PR heads, wikis)."""
    cfg, store = _setup(config, org)
    do_fetch(cfg, store, _names(repos), limit)
    store.close()


@app.command()
def scan(
    config: ConfigOpt = Path("config.toml"),
    repos: ReposOpt = None,
    limit: LimitOpt = None,
    org: OrgOpt = None,
    full: Annotated[bool, typer.Option(help="Rescan all history instead of only new commits")] = False,
    ner_scope: Annotated[Optional[str], typer.Option(help="off | targeted | all (overrides config)")] = None,
) -> None:
    """Scan fetched mirrors for personal data."""
    cfg, store = _setup(config, org)
    do_scan(cfg, store, _names(repos), limit, full, ner_scope)
    store.close()


@app.command()
def enrich(config: ConfigOpt = Path("config.toml")) -> None:
    """Look up GitHub usernames for commits that introduced findings."""
    cfg, store = _setup(config)
    n = enrich_logins(cfg, store, console)
    console.print(f"Resolved {n} new commit authors via GitHub GraphQL")
    store.close()


@app.command()
def report(config: ConfigOpt = Path("config.toml"),
           org: Annotated[Optional[str], typer.Option("--org", help="Only rebuild these organisations' folders "
                                                      "(default: every organisation in the inventory)")] = None,
           open_browser: Annotated[bool, typer.Option("--open", help="Open the summary in a browser")] = False) -> None:
    """Build a report folder per organisation (HTML, per-repo pages, CSV/JSON exports) and an index of them."""
    cfg, store = _setup(config)
    index = do_report(cfg, store, _orgs(org) if org is not None else None)
    store.close()
    if open_browser:
        webbrowser.open(index.resolve().as_uri())


@app.command()
def run(
    config: ConfigOpt = Path("config.toml"),
    repos: ReposOpt = None,
    limit: LimitOpt = None,
    org: OrgOpt = None,
    full: Annotated[bool, typer.Option(help="Rescan all history instead of only new commits")] = False,
    skip_fetch: Annotated[bool, typer.Option(help="Use existing mirrors without fetching")] = False,
    ner_scope: Annotated[Optional[str], typer.Option(help="off | targeted | all (overrides config)")] = None,
) -> None:
    """inventory, fetch, scan, enrich, teams and report in one go."""
    cfg, store = _setup(config, org)
    names = _names(repos)
    if not skip_fetch:
        do_inventory(cfg, store)
        do_fetch(cfg, store, names, limit)
    do_scan(cfg, store, names, limit, full, ner_scope)
    enrich_logins(cfg, store, console)
    do_teams(cfg, store)
    do_report(cfg, store)
    store.close()


@app.command()
def teams(config: ConfigOpt = Path("config.toml"), org: OrgOpt = None) -> None:
    """Record which GitHub teams have write, maintain or admin access to each repository."""
    cfg, store = _setup(config, org)
    do_teams(cfg, store)
    store.close()


@app.command()
def orgs(
    enterprise: Annotated[str, typer.Argument(help="Enterprise slug, as in github.com/enterprises/<slug>")],
    exclude: Annotated[Optional[str], typer.Option(help="Comma separated organisations to leave out")] = None,
) -> None:
    """List the organisations in a GitHub enterprise (needs enterprise membership and read:enterprise)."""
    skip = {o.lower() for o in _orgs(exclude)} if exclude else set()
    try:
        logins = [o for o in enterprise_orgs(enterprise, console) if o.lower() not in skip]
    except GitHubError as e:
        console.print(f"[red]Could not list organisations in {enterprise}: {e}[/]")
        console.print("You need to be an enterprise member, and `gh auth refresh -s read:enterprise`")
        raise typer.Exit(1)
    for login in logins:
        console.print(login)
    console.print(f"\n{len(logins)} organisations. For config.toml:\norgs = {json.dumps(logins)}", soft_wrap=True)


@triage_app.command("export")
def triage_export(
    out: Annotated[Path, typer.Argument(help="CSV file to write")] = Path("triage.csv"),
    config: ConfigOpt = Path("config.toml"),
    bands: Annotated[str, typer.Option(help="Comma separated bands to include")] = "High,Medium,Low",
    include_triaged: Annotated[bool, typer.Option(help="Include findings that already have a decision")] = False,
    org: Annotated[Optional[str], typer.Option("--org", help="Only these organisations (default: all)")] = None,
) -> None:
    """Write findings to CSV; fill in the status and note columns, then import."""
    _, store = _setup(config)
    n = export_triage(store, out, [b.strip() for b in bands.split(",")], include_triaged,
                      _orgs(org) if org is not None else None)
    store.close()
    console.print(f"Wrote {n} findings to {out}. Valid statuses: {', '.join(STATUSES)} (or 'clear' to reset)")


@triage_app.command("import")
def triage_import(
    file: Annotated[Path, typer.Argument(help="Edited triage CSV")],
    config: ConfigOpt = Path("config.toml"),
    reviewer: Annotated[Optional[str], typer.Option(help="Reviewer name (defaults to OS user)")] = None,
) -> None:
    """Record triage decisions; they carry over to future runs by fingerprint."""
    _, store = _setup(config)
    n, problems = import_triage(store, file, reviewer)
    store.close()
    for p in problems:
        console.print(f"[yellow]{p}[/]")
    console.print(f"Recorded {n} decisions. Rebuild the report with `pii-scan report`.")


if __name__ == "__main__":
    app()
