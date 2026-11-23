"""GitHub GraphQL helpers, with the gh CLI mocked out."""
import json
import subprocess

from pii_scanner import github


class FakeRun:
    def __init__(self, responses):
        self.responses = list(responses)
        self.queries = []

    def __call__(self, args, **kwargs):
        self.queries.append(args[args.index("-f") + 1])
        body = self.responses.pop(0)
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(body), stderr="")


RATE = {"cost": 1, "remaining": 4999, "resetAt": "2030-01-01T00:00:00Z"}


def test_commit_logins_batches_by_repository(monkeypatch):
    fake = FakeRun([{"data": {
        "rateLimit": RATE,
        "r0": {"c0": {"author": {"user": {"login": "alice"}}}, "c2": {"author": {"user": None}}},
        "r1": {"c1": None},
    }}])
    monkeypatch.setattr(subprocess, "run", fake)
    out = github.commit_logins([("O", "a", "1" * 40), ("O", "b", "2" * 40), ("O", "a", "3" * 40)])
    assert len(fake.queries) == 1
    assert out == {("O", "a", "1" * 40): "alice", ("O", "b", "2" * 40): "", ("O", "a", "3" * 40): ""}


def test_team_permissions_keep_write_and_inherit_from_parent(monkeypatch):
    teams = {"data": {"rateLimit": RATE, "organization": {"teams": {
        "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [
            {"slug": "parent", "name": "Parent", "parentTeam": None, "repositories": {
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "edges": [{"permission": "ADMIN", "node": {"name": "r1"}}, {"permission": "READ", "node": {"name": "r2"}}]}},
            {"slug": "child", "name": "Child", "parentTeam": {"slug": "parent"}, "repositories": {
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "edges": [{"permission": "WRITE", "node": {"name": "r3"}}]}},
        ]}}}}
    monkeypatch.setattr(subprocess, "run", FakeRun([teams]))
    rows = {(r["slug"], r["repo"]): r for r in github.team_repo_permissions("O")}
    assert set(rows) == {("parent", "r1"), ("child", "r3"), ("child", "r1")}
    assert rows[("child", "r1")]["inherited_from"] == "parent" and rows[("child", "r1")]["permission"] == "admin"
