from __future__ import annotations

import shutil
from pathlib import Path

from .gitutil import GitError, git

REFSPECS = (
    "+refs/heads/*:refs/heads/*",
    "+refs/tags/*:refs/tags/*",
    # Closed and unmerged PR commits stay publicly reachable on GitHub
    "+refs/pull/*/head:refs/pull/*/head",
)


def mirror_path(mirrors_dir: Path, org: str, name: str, wiki: bool = False) -> Path:
    return mirrors_dir / org / (f"{name}.wiki.git" if wiki else f"{name}.git")


def _init_mirror(path: Path, url: str, refspecs: tuple[str, ...]) -> None:
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "--bare", "--quiet")
    git(path, "remote", "add", "origin", url)
    git(path, "config", "--unset-all", "remote.origin.fetch", check=False)
    for spec in refspecs:
        git(path, "config", "--add", "remote.origin.fetch", spec)
    git(path, "config", "gc.auto", "0")


def fetch_mirror(path: Path, url: str, default_branch: str | None,
                 refspecs: tuple[str, ...] = REFSPECS) -> None:
    fresh = not (path / "HEAD").exists()
    if fresh:
        _init_mirror(path, url, refspecs)
    try:
        git(path, "fetch", "--prune", "--quiet", "--no-tags", "origin")
    except GitError:
        if fresh:
            shutil.rmtree(path, ignore_errors=True)
        raise
    if not default_branch:
        heads = git(path, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()
        default_branch = next((b for b in ("master", "main") if b in heads), heads[0] if heads else None)
    if default_branch:
        git(path, "symbolic-ref", "HEAD", f"refs/heads/{default_branch}")


def fetch_repo(mirrors_dir: Path, org: str, name: str, default_branch: str | None,
               has_wiki: bool, include_wikis: bool) -> tuple[str | None, bool]:
    """Returns (error, wiki_fetched)."""
    error = None
    try:
        fetch_mirror(mirror_path(mirrors_dir, org, name), f"https://github.com/{org}/{name}.git", default_branch)
    except GitError as e:
        error = str(e)
    wiki_ok = False
    if include_wikis and has_wiki:
        try:
            fetch_mirror(
                mirror_path(mirrors_dir, org, name, wiki=True),
                f"https://github.com/{org}/{name}.wiki.git",
                None,
                REFSPECS[:2],
            )
            wiki_ok = True
        except GitError:
            pass  # has_wiki is true for most repos even when no wiki page exists
    return error, wiki_ok
