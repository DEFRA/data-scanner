import os
import warnings
from dataclasses import dataclass

from pii_scanner import blobs
from pii_scanner.gitutil import BlobReader
from pii_scanner.runner import KILLED, scan_results


@dataclass
class FakeTask:
    org: str
    name: str


def fake_scan(task: FakeTask) -> dict:
    if task.name == "oom":
        os._exit(137)  # what the OOM killer looks like to the pool
    return {"org": task.org, "name": task.name, "sources": [], "error": None, "last_commit_at": None}


def test_killed_worker_only_fails_the_repo_that_caused_it():
    tasks = [FakeTask("O", f"ok{i}") for i in range(12)]
    tasks.insert(5, FakeTask("O", "oom"))
    tasks += [FakeTask("O", f"late{i}") for i in range(12)]
    results = {r["name"]: r for r in scan_results(tasks, workers=2, max_memory_mb=0, fn=fake_scan)}
    assert set(results) == {t.name for t in tasks}
    assert results["oom"]["error"] == KILLED
    assert all(r["error"] is None for name, r in results.items() if name != "oom")


def test_openpyxl_style_warnings_are_silenced(monkeypatch):
    def noisy(data, max_rows):
        warnings.warn("Unknown extension is not supported and will be removed", UserWarning)
        return [("Sheet!row 1", 1, "x")]

    monkeypatch.setattr(blobs, "_xlsx", noisy)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert blobs.extract_lines("xlsx", b"") == [("Sheet!row 1", 1, "x")]


def test_memory_watchdog_aborts_one_repo_and_records_an_error(tmp_path, monkeypatch):
    import time
    from pathlib import Path

    from pii_scanner import scanner
    from pii_scanner.config import load_config

    def hog(task, repo, source, classifier):
        chunks = []
        for _ in range(100):
            chunks.append(b"x" * (10 << 20))  # written pages, so resident memory really grows
            time.sleep(0.2)
        return []

    cfg = load_config(Path(__file__).resolve().parents[1] / "config.toml")
    task = scanner.ScanTask("O", "hog", tmp_path, None, {}, True, {}, cfg, b"k" * 32, "off")
    monkeypatch.setattr(scanner, "_scan_source", hog)
    monkeypatch.setattr(scanner, "_POLL_SECONDS", 0.05)
    try:
        scanner.init_worker(40)
        res = scanner.scan_repo(task)
        assert res["error"].startswith("MemoryBudgetExceeded") and res["sources"] == []
        monkeypatch.setattr(scanner, "_scan_source", lambda *a: [])
        assert scanner.scan_repo(task)["error"] is None  # the worker carries on with the next repo
    finally:
        scanner._mem["budget"] = 0


def test_extract_lines_distinguishes_unreadable_from_empty():
    assert blobs.extract_lines("xlsx", b"not a zip") is None
    assert blobs.extract_lines("txt", b"anything") == []


def test_blob_reader_skips_oversized_blobs_and_stays_in_sync(tmp_path):
    import subprocess

    repo = tmp_path / "r"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    big = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=b"x" * 3_000_000,
                         capture_output=True, check=True).stdout.decode().strip()
    small = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=b"hello",
                           capture_output=True, check=True).stdout.decode().strip()
    reader = BlobReader(repo)
    assert reader.read(big, 1000) is None and reader.last_too_large and reader.last_size == 3_000_000
    assert reader.read(small, 1000) == b"hello" and not reader.last_too_large
    assert reader.read("0" * 40) is None and not reader.last_too_large
    reader.close()
