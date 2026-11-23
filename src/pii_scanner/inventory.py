from __future__ import annotations

import json
import subprocess

from .config import Config
from .store import Store


def list_public_repos(org: str) -> list[dict]:
    proc = subprocess.run(
        ["gh", "api", "--paginate", f"orgs/{org}/repos?type=public&per_page=100", "--jq", ".[] | @json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def refresh_inventory(cfg: Config, store: Store) -> dict[str, int]:
    counts = {}
    for org in cfg.orgs:
        repos = [
            r for r in list_public_repos(org)
            if (cfg.include_forks or not r["fork"])
            and r["name"] not in cfg.exclude_repos
            and r.get("visibility", "public") == "public"
        ]
        store.upsert_inventory(org, repos)
        counts[org] = len(repos)
    return counts
