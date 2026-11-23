from __future__ import annotations

import os
import subprocess
from pathlib import Path

GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}


class GitError(RuntimeError):
    pass


def git(repo: Path, *args: str, check: bool = True, input_bytes: bytes | None = None) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        env=GIT_ENV,
        input=input_bytes,
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args[:3])} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout.decode("utf-8", errors="replace")


def git_popen(repo: Path, *args: str) -> subprocess.Popen:
    return subprocess.Popen(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=GIT_ENV,
    )


class BlobReader:
    """Long-running `git cat-file --batch` for reading file contents at a revision."""

    def __init__(self, repo: Path):
        self.proc = subprocess.Popen(
            ["git", "-C", str(repo), "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=GIT_ENV,
        )
        self.repo = repo
        self._check: subprocess.Popen | None = None
        self.last_size = 0
        self.last_too_large = False

    def _discard(self, n: int) -> None:
        while n > 0:
            chunk = self.proc.stdout.read(min(n, 1 << 20))
            if not chunk:
                break
            n -= len(chunk)

    def read(self, spec: str, max_bytes: int | None = None) -> bytes | None:
        """Blob contents, or None if missing, not a blob, or larger than max_bytes (see last_too_large)."""
        self.last_size, self.last_too_large = 0, False
        if "\n" in spec:
            return None
        self.proc.stdin.write(spec.encode() + b"\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline().decode(errors="replace").rstrip("\n")
        if line.endswith((" missing", " ambiguous")) or not line:
            return None
        _, obj_type, size_s = line.split()[:3]
        size = int(size_s)
        self.last_size = size
        if obj_type != "blob":
            self._discard(size + 1)
            return None
        if max_bytes is not None and size > max_bytes:
            self._discard(size + 1)
            self.last_too_large = True
            return None
        data = self.proc.stdout.read(size)
        self.proc.stdout.read(1)
        return data

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        if self.proc.stdout:
            self.proc.stdout.close()  # unblocks git if it was mid-write when a scan was aborted
        self.proc.wait()
        if self._check:
            self._check.stdin.close()
            self._check.stdout.close()
            self._check.wait()

    def oid(self, spec: str) -> str | None:
        """Object id for a revision spec such as HEAD:path, without reading the object."""
        if "\n" in spec:
            return None
        if self._check is None:
            self._check = subprocess.Popen(
                ["git", "-C", str(self.repo), "cat-file", "--batch-check=%(objectname) %(objecttype)"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=GIT_ENV,
            )
        self._check.stdin.write(spec.encode() + b"\n")
        self._check.stdin.flush()
        parts = self._check.stdout.readline().decode(errors="replace").split()
        return parts[0] if len(parts) == 2 and parts[1] == "blob" else None


def read_prefix(repo: Path, sha: str, max_bytes: int) -> bytes:
    """First max_bytes of a blob without loading the rest."""
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "blob", sha],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=GIT_ENV)
    try:
        return proc.stdout.read(max_bytes)
    finally:
        proc.stdout.close()
        proc.kill()
        proc.wait()


def iter_blobs(repo: Path, rev_args: list[str]):
    """Yield (sha, size, path) for every blob reachable from rev_args, streamed to keep memory flat."""
    rev = subprocess.Popen(["git", "-C", str(repo), "rev-list", "--objects", *rev_args],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=GIT_ENV)
    check = subprocess.Popen(
        ["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(rest)"],
        stdin=rev.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=GIT_ENV,
    )
    rev.stdout.close()
    try:
        for raw in check.stdout:
            parts = raw.decode("utf-8", errors="replace").rstrip("\n").split(" ", 3)
            if len(parts) == 4 and parts[1] == "blob" and parts[3]:
                yield parts[0], int(parts[2]), parts[3]
    finally:
        check.stdout.close()
        for p in (check, rev):
            if p.poll() is None:
                p.kill()
            p.wait()
