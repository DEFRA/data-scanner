from __future__ import annotations

import json
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
from .gitutil import git
from .inventory import refresh_inventory
from .report import build_report
from .runner import auto_memory_limit_mb, scan_results
from .scanner import ScanTask
from .store import Store, now
from .triage import STATUSES, export_triage, import_triage

app = typer.Typer(no_args_is_help=True, help="Scan a GitHub organisation's public repositories for leaked personal data.")
triage_app = typer.Typer(no_args_is_help=True, help="Export findings for review and import decisions.")
app.add_typer(triage_app, name="triage")
console = Console()

ConfigOpt = Annotated[Path, typer.Option("--config", "-c", help="Path to config.toml")]
ReposOpt = Annotated[Optional[str], typer.Option(help="Comma separated repo names to limit to")]
LimitOpt = Annotated[Optional[int], typer.Option(help="Only process the first N repos (alphabetical)")]


def _setup(config: Path) -> tuple[Config, Store]:
    cfg = load_config(config)
    return cfg, Store(cfg.db_path)


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
    for org, n in refresh_inventory(cfg, store).items():
        console.print(f"{org}: {n} public repositories in scope")
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
    repos = store.repos(names, limit)
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
    repos = [r for r in store.repos(names, limit)
             if (mirror_path(cfg.mirrors_dir, r["org"], r["name"]) / "HEAD").exists()]
    if not repos:
        console.print("[yellow]No fetched repositories to scan; run `pii-scan fetch` first[/]")
        raise typer.Exit(1)
    run_id = store.start_run("full" if full else "incremental")
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


def do_report(cfg: Config, store: Store) -> Path:
    index = build_report(store, cfg.reports_dir, cfg.orgs)
    console.print(f"Report written to {index}")
    return index


@app.command()
def inventory(config: ConfigOpt = Path("config.toml")) -> None:
    """List the organisation's public, non-fork repositories via gh."""
    cfg, store = _setup(config)
    do_inventory(cfg, store)
    store.close()


@app.command()
def fetch(config: ConfigOpt = Path("config.toml"), repos: ReposOpt = None, limit: LimitOpt = None) -> None:
    """Create or update local bare mirrors (branches, tags, PR heads, wikis)."""
    cfg, store = _setup(config)
    do_fetch(cfg, store, _names(repos), limit)
    store.close()


@app.command()
def scan(
    config: ConfigOpt = Path("config.toml"),
    repos: ReposOpt = None,
    limit: LimitOpt = None,
    full: Annotated[bool, typer.Option(help="Rescan all history instead of only new commits")] = False,
    ner_scope: Annotated[Optional[str], typer.Option(help="off | targeted | all (overrides config)")] = None,
) -> None:
    """Scan fetched mirrors for personal data."""
    cfg, store = _setup(config)
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
           open_browser: Annotated[bool, typer.Option("--open", help="Open the summary in a browser")] = False) -> None:
    """Build the HTML summary, per-repo pages and CSV/JSON exports."""
    cfg, store = _setup(config)
    index = do_report(cfg, store)
    store.close()
    if open_browser:
        webbrowser.open(index.resolve().as_uri())


@app.command()
def run(
    config: ConfigOpt = Path("config.toml"),
    repos: ReposOpt = None,
    limit: LimitOpt = None,
    full: Annotated[bool, typer.Option(help="Rescan all history instead of only new commits")] = False,
    skip_fetch: Annotated[bool, typer.Option(help="Use existing mirrors without fetching")] = False,
    ner_scope: Annotated[Optional[str], typer.Option(help="off | targeted | all (overrides config)")] = None,
) -> None:
    """inventory, fetch, scan, enrich, teams and report in one go."""
    cfg, store = _setup(config)
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
def teams(config: ConfigOpt = Path("config.toml")) -> None:
    """Record which GitHub teams have write, maintain or admin access to each repository."""
    cfg, store = _setup(config)
    do_teams(cfg, store)
    store.close()


@triage_app.command("export")
def triage_export(
    out: Annotated[Path, typer.Argument(help="CSV file to write")] = Path("triage.csv"),
    config: ConfigOpt = Path("config.toml"),
    bands: Annotated[str, typer.Option(help="Comma separated bands to include")] = "High,Medium,Low",
    include_triaged: Annotated[bool, typer.Option(help="Include findings that already have a decision")] = False,
) -> None:
    """Write findings to CSV; fill in the status and note columns, then import."""
    _, store = _setup(config)
    n = export_triage(store, out, [b.strip() for b in bands.split(",")], include_triaged)
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
