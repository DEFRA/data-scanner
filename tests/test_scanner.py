"""End-to-end scan of a synthetic git repository. All personal-looking values are synthetic."""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from openpyxl import Workbook

from pii_scanner.config import load_config
from pii_scanner.report import build_report
from pii_scanner.scanner import ScanTask, scan_repo
from pii_scanner.store import Store

from test_extended import _jpeg_with_exif

ROOT = Path(__file__).resolve().parents[1]
RAW_VALUES = ("jonathan.watson.fx@gmail.com", "07911 482736", "JT482739B", "jon.watson.fx@outlook.com",
              "john.watson.fx@hotmail.co.uk", "j.watson.fx@gmail.com", "1103847261", "14/07/1983", "Watson-Hale")


def sh(repo: Path, *args: str, author: str = "Alice Dev <alice@dev.example>") -> str:
    name, email = author[:-1].split(" <")
    env = {**os.environ, "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": name,
           "GIT_COMMITTER_EMAIL": email, "GIT_AUTHOR_DATE": os.environ.get("_DATE", "2024-01-01T10:00:00Z")}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()


def commit(repo: Path, msg: str, date: str, author: str = "Alice Dev <alice@dev.example>") -> str:
    os.environ["_DATE"] = date
    sh(repo, "add", "-A", author=author)
    sh(repo, "commit", "-q", "-m", msg, author=author)
    return sh(repo, "rev-parse", "HEAD")


@pytest.fixture()
def repo(tmp_path: Path) -> dict:
    r = tmp_path / "repo"
    r.mkdir()
    sh(r, "init", "-q", "-b", "main")
    (r / "data").mkdir()
    (r / "data" / "customers.csv").write_text(
        "name,email,phone\nJonathan Watson,jonathan.watson.fx@gmail.com,07911 482736\n")
    c1 = commit(r, "add customers", "2024-01-01T10:00:00Z")

    (r / "tests").mkdir()
    (r / "tests" / "user.test.js").write_text(
        "import { faker } from '@faker-js/faker'\nconst user = { email: 'john.watson.fx@hotmail.co.uk' }\n")
    (r / "src").mkdir()
    (r / "src" / "contacts.js").write_text("// owner\nconst owner = 'jon.watson.fx@outlook.com'\n")
    wb = Workbook()
    wb.active.append(["Name", "Email"])
    wb.active.append(["Jon Watson", "jon.watson.fx@outlook.com"])
    wb.save(r / "data" / "export.xlsx")
    (r / "Test Data").mkdir()
    (r / "Test Data" / "user one.json").write_text('{"email": "j.watson.fx@gmail.com"}\n')
    rows = ["name,dob,crn"] + [f"Person {i},," for i in range(6)]
    (r / "data" / "people.csv").write_text("\n".join(rows) + "\n")
    (r / "photos").mkdir()
    (r / "data" / "broken.xlsx").write_bytes(b"not a zip archive")
    (r / "photos" / "visit.jpg").write_bytes(_jpeg_with_exif())
    (r / "docs").mkdir()
    (r / "cases").mkdir()
    (r / "cases" / "letter.txt").write_text("Dear Mrs Watson-Hale,\n\nYou told us you were diagnosed with diabetes.\n")
    (r / "docs" / "ui.md").write_text("The button is disabled.\nMedication reminders feature.\n")
    # Deliberate, published or internal contact details that must not be reported
    (r / "README.md").write_text("Contact Johnny Watson on johnny.watson.fx@gmail.com or 07911 556204.\n"
                                 "Example NI number JT 48 27 39 B\n")
    (r / "package.json").write_text('{"author": "Johnnie Watson <johnnie.watson.fx@gmail.com>"}\n')
    (r / "app" / "views").mkdir(parents=True)
    (r / "app" / "views" / "contact.njk").write_text("<p>Call 07911 334512</p>\n")
    (r / "src" / "config.js").write_text("const team = 'Jonny Watson, jonny.watson.fx@defra.gov.uk, 07911 778301'\n")
    c2 = commit(r, "tests and export", "2024-02-01T10:00:00Z", author="Bob Coder <bob@dev.example>")

    (r / "data" / "customers.csv").unlink()
    with open(r / "data" / "people.csv", "a") as fh:
        fh.write("Ada Pemberton,14/07/1983,1103847261\n")
    c3 = commit(r, "remove customers", "2024-03-01T10:00:00Z")

    sh(r, "checkout", "-q", "-b", "pr-branch")
    (r / "src" / "app.js").write_text("const ni = 'JT482739B' // national insurance\n")
    pr = commit(r, "pr only", "2024-04-01T10:00:00Z")
    sh(r, "update-ref", "refs/pull/1/head", pr)
    sh(r, "checkout", "-q", "main")
    sh(r, "branch", "-q", "-D", "pr-branch")
    return {"path": r, "c1": c1, "c2": c2, "c3": c3, "pr": pr}


def make_task(repo_path: Path, tmp_path: Path, old_tips=None, ner_scope="off", max_document_bytes=None) -> ScanTask:
    cfg = load_config(ROOT / "config.toml")
    cfg.data_dir = tmp_path / "data"
    cfg.reports_dir = tmp_path / "reports"
    if max_document_bytes:
        cfg.max_document_bytes = max_document_bytes
    return ScanTask("TESTORG", "demo", repo_path, None, {"code": old_tips, "wiki": None}, old_tips is None,
                    {}, cfg, b"k" * 32, ner_scope)


def by_source(res: dict, source: str):
    return next(s for s in res["sources"] if s.source == source)


def test_history_attribution_and_tiers(repo, tmp_path):
    res = scan_repo(make_task(repo["path"], tmp_path))
    assert res["error"] is None, res["error"]
    code = by_source(res, "code")
    by_key = {(f["path"], f["rule"]): f for f in code.findings}

    email = by_key[("data/customers.csv", "email")]
    assert email["commit_sha"] == repo["c1"]
    assert email["author_name"] == "Alice Dev"
    assert email["line"] == 2
    assert email["queue"] == "A" and email["tier"] == "data"
    assert email["band"] == "High"
    assert email["fingerprint"] not in code.head_present  # deleted in c3

    test_email = by_key[("tests/user.test.js", "email")]
    assert test_email["queue"] == "B"
    assert any("fake data library" in r for r in test_email["reasons"])
    assert test_email["score"] < email["score"]

    still_there = by_key[("src/contacts.js", "email")]
    assert still_there["fingerprint"] in code.head_present
    assert still_there["author_name"] == "Bob Coder"

    pr_only = by_key[("src/app.js", "nino")]
    assert pr_only["commit_sha"] == repo["pr"]

    spaced = by_key[("Test Data/user one.json", "email")]
    assert spaced["tier"] == "test" and spaced["queue"] == "B"

    doc = by_source(res, "document")
    docs = {(f["path"], f["rule"]): f for f in doc.findings}
    xl = docs[("data/export.xlsx", "email")]
    assert xl["location"] == "Sheet!row 2"
    assert xl["commit_sha"] == repo["c2"]
    assert xl["fingerprint"] in doc.head_present
    photo = docs[("photos/visit.jpg", "media")]
    assert "camera EXIF" in photo["masked"] and photo["fingerprint"] in doc.head_present
    gps = docs[("photos/visit.jpg", "location")]
    assert gps["masked"].startswith("53.8")

    dob = by_key[("data/people.csv", "dob")]
    assert dob["commit_sha"] == repo["c3"] and dob["line"] == 8  # header came from the blob, not the hunk
    assert by_key[("data/people.csv", "customer_ref")]["masked"].startswith("CRN ")
    assert ("cases/letter.txt", "special_category") in by_key
    assert ("cases/letter.txt", "person_name") in by_key
    assert ("docs/ui.md", "special_category") not in by_key  # no identifiable person nearby

    # Published, manifest and internal content is not reported, but serious identifiers still are
    rules_by_path = {}
    for (path, rule) in by_key:
        rules_by_path.setdefault(path, set()).add(rule)
    assert rules_by_path.get("README.md") == {"nino"}
    assert "package.json" not in rules_by_path
    assert "app/views/contact.njk" not in rules_by_path
    assert rules_by_path.get("src/config.js") == {"uk_phone"}  # the staff name and .gov.uk email are dropped

    dumped = json.dumps([f for s in res["sources"] for f in s.findings])
    for raw in RAW_VALUES:
        assert raw not in dumped


def test_unreadable_and_oversized_documents_are_recorded(repo, tmp_path):
    res = scan_repo(make_task(repo["path"], tmp_path))
    skipped = {d["path"]: d for d in by_source(res, "document").skipped_docs}
    assert set(skipped) == {"data/broken.xlsx"}
    assert skipped["data/broken.xlsx"]["reason"] == "unreadable"
    assert skipped["data/broken.xlsx"]["commit_sha"] == repo["c2"]

    small = scan_repo(make_task(repo["path"], tmp_path, max_document_bytes=30))
    skipped = {d["path"]: d["reason"] for d in by_source(small, "document").skipped_docs}
    assert skipped["data/export.xlsx"] == "too large"
    assert skipped["photos/visit.jpg"] == "too large"
    assert skipped["data/broken.xlsx"] == "unreadable"  # 17 bytes, under the limit


def test_incremental_skip_and_new_commits(repo, tmp_path):
    first = scan_repo(make_task(repo["path"], tmp_path))
    tips = by_source(first, "code").tips
    again = scan_repo(make_task(repo["path"], tmp_path, old_tips=tips))
    assert by_source(again, "code").skipped

    (repo["path"] / "src" / "more.js").write_text("const x = 'john.watson.fx@yahoo.co.uk'\n")
    commit(repo["path"], "more", "2024-05-01T10:00:00Z")
    inc = scan_repo(make_task(repo["path"], tmp_path, old_tips=tips))
    code = by_source(inc, "code")
    assert not code.skipped and not code.full
    assert [f["path"] for f in code.findings] == ["src/more.js"]


def test_store_and_report_do_not_leak_raw_values(repo, tmp_path):
    res = scan_repo(make_task(repo["path"], tmp_path))
    store = Store(tmp_path / "db.sqlite")
    store.upsert_inventory("TESTORG", [{"name": "demo", "html_url": "https://github.com/TESTORG/demo",
                                        "archived": True, "fork": False, "default_branch": "main"}])
    run_id = store.start_run("full")
    for s in res["sources"]:
        store.save_repo_findings(run_id, "TESTORG", "demo", s.source, s.findings, s.full)
        store.set_in_head("TESTORG", "demo", s.source, s.head_present)
        if s.source == "document":
            store.save_skipped_docs("TESTORG", "demo", s.skipped_docs, replace=s.full)
    store.finish_run(run_id, 1, 0)
    store.replace_repo_teams("TESTORG", [{"repo": "demo", "slug": "flood-devs", "name": "Flood Devs",
                                          "permission": "write"}])
    index = build_report(store, tmp_path / "reports", ["TESTORG"])
    html = index.read_text()
    assert "demo" in html and "Documents not scanned" in html and "Flood Devs" in html
    reports = tmp_path / "reports"
    assert "Flood Devs" in (reports / "teams.html").read_text()
    assert (reports / "teams" / "flood-devs.html").exists()
    assert "Bob Coder" in (reports / "authors.html").read_text()
    for name in ("by-repo.csv", "by-team.csv", "by-author.csv", "repos/TESTORG__demo.csv", "teams/flood-devs.csv"):
        assert (reports / "exports" / name).exists(), name
    assert "Flood Devs" in (reports / "exports" / "teams" / "flood-devs.csv").read_text()
    repo_page = (tmp_path / "reports" / "repos" / "TESTORG__demo.html").read_text()
    assert "data/broken.xlsx" in repo_page
    assert f"https://github.com/TESTORG/demo/blob/{repo['c1']}/data/customers.csv#L2" in repo_page
    assert "History only" in repo_page and "Still present" in repo_page
    assert (reports / "assets" / "report.min.css").exists() and (reports / "assets" / "defra-logo.svg").exists()
    assert 'href="../assets/report.min.css"' in repo_page
    assert 'href="teams.html" aria-current="page"' in (reports / "teams.html").read_text()
    for page in reports.rglob("*.html"):
        # The report must work offline and never load anything from outside reports/
        external = re.findall(r'<(?:link|script|img)\b[^>]*\b(?:href|src)="(?:https?:)?//', page.read_text())
        assert not external, f"{page} loads external resources: {external}"
    for f in (tmp_path / "reports").rglob("*"):
        if f.is_file():
            text = f.read_text()
            for raw in RAW_VALUES:
                assert raw not in text, f"{raw} leaked into {f}"
    store.close()


def test_report_splits_archived_and_orders_by_repo_priority(repo, tmp_path):
    res = scan_repo(make_task(repo["path"], tmp_path))
    store = Store(tmp_path / "db.sqlite")
    store.upsert_inventory("TESTORG", [
        {"name": "demo", "html_url": "https://github.com/TESTORG/demo", "archived": True, "fork": False,
         "default_branch": "main"},
        {"name": "live", "html_url": "https://github.com/TESTORG/live", "archived": False, "fork": False,
         "default_branch": "main"},
    ])
    run_id = store.start_run("full")
    for s in res["sources"]:
        store.save_repo_findings(run_id, "TESTORG", "demo", s.source, s.findings, s.full)
        # "live" gets only the code findings, so it has fewer and ranks below "demo"
        if s.source == "code":
            store.save_repo_findings(run_id, "TESTORG", "live", s.source,
                                     [{**f, "repo": "live", "fingerprint": "live-" + f["fingerprint"]}
                                      for f in s.findings], s.full)
    store.finish_run(run_id, 2, 0)
    reports = tmp_path / "reports"
    build_report(store, reports, ["TESTORG"])
    store.close()

    index = (reports / "index.html").read_text()
    assert "1 active and 1 archived repositories have findings needing review" in index
    assert "Repositories by band" in index
    assert "2 with findings,\n  of which 2 (1 active, 1 archived) need review." in index
    assert 'href="queue-a.html?band=High&amp;archived=1"' in index

    import csv
    rows = list(csv.DictReader(open(reports / "findings.csv", encoding="utf-8")))
    assert {r["repo"]: r["priority"] for r in rows} == {"demo": "1", "live": "2"}

    for page in ("queue-a.html", "queue-b.html"):
        html = (reports / page).read_text()
        order = re.findall(r'href="repos/TESTORG__(\w+)\.html"', html)
        if order:
            # Grouped by repository, highest priority first
            assert order == sorted(order, key=["demo", "live"].index), page
        if 'data-archived="0"' in html:
            assert 'data-archived="1"' in html and 'data-filter-key="archived"' in html
        data = re.search(r'<script type="application/json" id="findings-data">(.*?)</script>', html, re.S)
        if data:
            payload = json.loads(data.group(1))
            assert payload["fields"][0] == "priority"
            assert len(payload["rows"]) == html.count('<tr class="govuk-table__row" data-i=')
    spacy = pytest.importorskip("spacy")
    cfg = load_config(ROOT / "config.toml")
    if not spacy.util.is_package(cfg.ner_model):
        pytest.skip("spaCy model not installed")
    res = scan_repo(make_task(repo["path"], tmp_path, ner_scope="targeted"))
    names = [f for s in res["sources"] for f in s.findings if f["rule"] == "person_name"]
    assert names, "expected at least one person name from the CSV or spreadsheet"
    assert all("Watson" not in f["masked"] for f in names)
    paths = {f["path"] for f in names}
    assert "src/config.js" not in paths  # next to an internal .gov.uk address, so treated as staff
    assert "README.md" not in paths and "package.json" not in paths


def test_staff_names_and_emails_are_ignored(repo, tmp_path):
    from pii_scanner import scanner

    try:
        scanner.set_staff(["Jon Watson"], ["jonathan.watson.fx@gmail.com"])
        res = scan_repo(make_task(repo["path"], tmp_path))
    finally:
        scanner.set_staff([], [])
    found = {(f["path"], f["rule"]) for s in res["sources"] for f in s.findings}
    assert ("data/customers.csv", "email") not in found
    assert ("data/customers.csv", "uk_phone") in found


def test_linked_data_needs_a_person_even_in_data_files(repo, tmp_path):
    (repo["path"] / "data" / "properties.csv").write_text(
        "address,postcode,lat,lon\n14 Hawthorn Close,LS1 4AP,53.80081,-1.54912\n")
    (repo["path"] / "data" / "owners.csv").write_text(
        "name,email,address,postcode\nJonnie Watson,jonnie.watson.fx@gmail.com,14 Hawthorn Close,LS1 4AP\n")
    commit(repo["path"], "geo", "2024-06-01T10:00:00Z")
    res = scan_repo(make_task(repo["path"], tmp_path))
    found = {(f["path"], f["rule"]) for f in by_source(res, "code").findings}
    assert not {r for p, r in found if p == "data/properties.csv"}
    assert {("data/owners.csv", "postcode"), ("data/owners.csv", "street_address")} <= found


def test_large_files_are_sampled_not_diffed(repo, tmp_path):
    rows = ["name,email"] + [f"Row {i},r{i}x@example.org" for i in range(40)] + ["Jonnie Watson,jonnie.watson.fx@gmail.com"]
    rows += [f"Tail {i},t{i}x@example.org" for i in range(40)]
    (repo["path"] / "data" / "big.csv").write_text("\n".join(rows) + "\n")
    sha = commit(repo["path"], "big", "2024-06-01T10:00:00Z")
    task = make_task(repo["path"], tmp_path)
    task.cfg.large_file_bytes = 500
    task.cfg.large_file_sample_lines = 60
    res = scan_repo(task)
    big = [f for f in by_source(res, "code").findings if f["path"] == "data/big.csv"]
    assert [f["rule"] for f in big] == ["email"]
    assert big[0]["commit_sha"] == sha and big[0]["line"] == 42
    assert any("only the first 60 lines" in r for r in big[0]["reasons"])


def test_head_check_skips_unchanged_files(repo, tmp_path):
    first = scan_repo(make_task(repo["path"], tmp_path))
    code = by_source(first, "code")
    tips = code.tips
    (repo["path"] / "src" / "more.js").write_text("const x = 'john.watson.fx@yahoo.co.uk'\n")
    commit(repo["path"], "more", "2024-05-01T10:00:00Z")
    task = make_task(repo["path"], tmp_path, old_tips=tips)
    task.known_paths = {"code": {f["path"]: [f["rule"]] for f in code.findings}}
    task.head_checks = {"code": code.head_checked}
    inc = by_source(scan_repo(task), "code")
    assert set(inc.head_checked) == {"src/more.js"}
