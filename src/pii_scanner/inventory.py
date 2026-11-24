from __future__ import annotations

import json
import subprocess
import time

from .config import Config
from .store import Store


def list_public_repos(org: str, attempts: int = 3) -> list[dict]:
    for attempt in range(1, attempts + 1):
        proc = subprocess.run(
            ["gh", "api", "--paginate", f"orgs/{org}/repos?type=public&per_page=100", "--jq", ".[] | @json"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        if attempt < attempts:
            time.sleep(5 * attempt)
    raise RuntimeError((proc.stderr or proc.stdout or f"gh exited {proc.returncode}").strip().splitlines()[-1])


def refresh_inventory(cfg: Config, store: Store) -> tuple[dict[str, int], dict[str, str]]:
    """Repo counts per organisation, and errors for organisations that could not be listed (left unchanged)."""
    counts, errors = {}, {}
    for org in cfg.orgs:
        try:
            listed = list_public_repos(org)
        except RuntimeError as e:
            errors[org] = str(e)
            continue
        repos = [
            r for r in listed
            if (cfg.include_forks or not r["fork"])
            and r["name"] not in cfg.exclude_repos
            and r.get("visibility", "public") == "public"
        ]
        store.upsert_inventory(org, repos)
        counts[org] = len(repos)
    return counts, errors
