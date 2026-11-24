import csv
import json

import pytest
import typer

from pii_scanner.cli import _orgs
from pii_scanner.report import build_report
from pii_scanner.store import Store


def finding(org: str, repo: str, fp: str, band: str = "High") -> dict:
    return {
        "fingerprint": fp, "org": org, "repo": repo, "source": "code", "rule": "email", "category": "Email address",
        "masked": "j***@example.com", "value_hash": "h-" + fp, "path": "src/a.js", "line": 1, "location": None,
        "commit_sha": "a" * 40, "author_name": "Dev", "author_email": "dev@example.com",
        "author_date": "2024-01-01T00:00:00Z", "tier": "code", "queue": "A", "score": 0.9, "band": band,
        "reasons": ["test"], "occurrences": 1, "in_head": 1,
    }


def inventory(store: Store, org: str, *names: str) -> None:
    store.upsert_inventory(org, [{"name": n, "html_url": f"https://github.com/{org}/{n}", "archived": False,
                                  "fork": False, "default_branch": "main"} for n in names])


def run(store: Store, orgs: list[str], findings: list[dict]) -> int:
    run_id = store.start_run("incremental", orgs)
    for f in findings:
        store.save_repo_findings(run_id, f["org"], f["repo"], "code", [f], False)
    store.finish_run(run_id, len(findings), 0)
    return run_id


def test_report_is_split_per_org(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    inventory(store, "ORGA", "shared", "alpha")
    inventory(store, "ORGB", "shared")
    run(store, ["ORGA", "ORGB"], [finding("ORGA", "shared", "a1"), finding("ORGA", "alpha", "a2"),
                                  finding("ORGB", "shared", "b1")])
    reports = tmp_path / "reports"
    (reports / "stale.html").parent.mkdir(parents=True)
    (reports / "stale.html").write_text("old flat report")
    top = build_report(store, reports)
    store.close()

    assert not (reports / "stale.html").exists()
    for org, fps in (("ORGA", {"a1", "a2"}), ("ORGB", {"b1"})):
        rows = list(csv.DictReader(open(reports / org / "findings.csv", encoding="utf-8")))
        assert {r["fingerprint"] for r in rows} == fps
        assert {r["org"] for r in rows} == {org}
        assert {r["fingerprint"] for r in json.loads((reports / org / "findings.json").read_text())} == fps
        by_repo = list(csv.DictReader(open(reports / org / "exports" / "by-repo.csv", encoding="utf-8")))
        assert {r["org"] for r in by_repo} == {org}
        assert (reports / org / "assets" / "report.min.css").exists()
        other = "ORGB" if org == "ORGA" else "ORGA"
        for page in (reports / org).rglob("*"):
            if page.is_file() and page.suffix in (".html", ".csv", ".json"):
                assert f"{other}__" not in page.read_text(), page
    html = top.read_text()
    assert 'href="ORGA/index.html"' in html and 'href="ORGB/index.html"' in html
    assert "j***@example.com" not in html


def test_report_for_one_org_keeps_other_folders(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    inventory(store, "ORGA", "alpha")
    inventory(store, "ORGB", "beta")
    run(store, ["ORGA", "ORGB"], [finding("ORGA", "alpha", "a1"), finding("ORGB", "beta", "b1")])
    reports = tmp_path / "reports"
    build_report(store, reports)
    marker = reports / "ORGA" / "marker"
    marker.write_text("kept")
    build_report(store, reports, ["ORGB"])
    store.close()
    assert marker.exists() and (reports / "ORGB" / "index.html").exists()


def test_new_findings_are_compared_per_org(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    inventory(store, "ORGA", "alpha")
    inventory(store, "ORGB", "beta")
    inventory(store, "ORGC", "gamma")
    run(store, ["ORGA"], [finding("ORGA", "alpha", "a1")])
    run(store, ["ORGA"], [finding("ORGA", "alpha", "a2")])
    # Later runs of other organisations must not make ORGA's findings look new
    run(store, ["ORGB"], [finding("ORGB", "beta", "b1")])
    run(store, ["ORGC"], [finding("ORGC", "gamma", "c1")])
    reports = tmp_path / "reports"
    build_report(store, reports)
    store.close()

    new = {org: {r["fingerprint"] for r in csv.DictReader(open(reports / org / "findings.csv", encoding="utf-8"))
                 if r["is_new"] == "True"} for org in ("ORGA", "ORGB", "ORGC")}
    assert new == {"ORGA": {"a2"}, "ORGB": set(), "ORGC": set()}
    assert "first completed run" in (reports / "ORGB" / "index.html").read_text()


def test_repos_filtered_by_org(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    inventory(store, "ORGA", "shared", "alpha")
    inventory(store, "ORGB", "shared")
    assert [(r["org"], r["name"]) for r in store.repos(orgs=["ORGB"])] == [("ORGB", "shared")]
    assert [(r["org"], r["name"]) for r in store.repos(["shared"], orgs=["ORGA"])] == [("ORGA", "shared")]
    assert len(store.repos()) == 3
    store.close()


def test_existing_runs_are_assigned_to_inventory_orgs(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    inventory(store, "DEFRA", "alpha")
    store.db.execute("INSERT INTO runs (started_at, finished_at, mode) VALUES ('t', 't', 'full')")
    store.db.commit()
    store.db.execute("UPDATE runs SET orgs = NULL")
    store.close()

    store = Store(tmp_path / "db.sqlite")
    inventory(store, "OTHER", "beta")
    assert [r["orgs"] for r in store.db.execute("SELECT orgs FROM runs")] == ['["DEFRA"]']
    assert len(store.latest_runs(2, "DEFRA")) == 1 and not store.latest_runs(2, "OTHER")
    store.close()


def test_inventory_skips_unreachable_org_and_keeps_its_repos(tmp_path, monkeypatch):
    from pii_scanner import inventory as inv
    from pii_scanner.config import Config

    store = Store(tmp_path / "db.sqlite")
    inventory(store, "ORGA", "alpha")

    def listing(org, attempts=3):
        if org == "ORGA":
            raise RuntimeError("connection reset")
        return [{"name": "beta", "html_url": "https://github.com/ORGB/beta", "archived": False, "fork": False}]

    monkeypatch.setattr(inv, "list_public_repos", listing)
    counts, errors = inv.refresh_inventory(Config(orgs=["ORGA", "ORGB"]), store)
    assert counts == {"ORGB": 1} and errors == {"ORGA": "connection reset"}
    assert [(r["org"], r["name"]) for r in store.repos()] == [("ORGA", "alpha"), ("ORGB", "beta")]
    store.close()


@pytest.mark.parametrize("value", ["../etc", "a/b", "", ",", "-lead", "x" * 40])
def test_org_option_rejects_non_logins(value):
    with pytest.raises(typer.BadParameter):
        _orgs(value)


def test_org_option_parses_list():
    assert _orgs(" DEFRA, Defra-Digital ") == ["DEFRA", "Defra-Digital"]
