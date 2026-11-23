from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool

from .scanner import ScanTask, init_worker, scan_repo

KILLED = "Worker process was killed by the OS (probably out of memory) while scanning this repository"


SPACY_BASELINE_MB = 400  # resident size of a loaded en_core_web_md, not counted against a repo's budget


def auto_memory_limit_mb(workers: int) -> int:
    """Per repo memory growth allowed: 80% of available RAM, minus each worker's model, shared across workers.

    Returns 0 (no cap) where /proc/meminfo is unavailable."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    available_mb = int(line.split()[1]) // 1024
                    workers = max(1, workers)
                    return max(768, int((available_mb * 0.8 - workers * SPACY_BASELINE_MB) / workers))
    except (OSError, ValueError):
        pass
    return 0


def _killed_result(task: ScanTask) -> dict:
    return {"org": task.org, "name": task.name, "sources": [], "error": KILLED, "last_commit_at": None}


def scan_results(tasks: list[ScanTask], workers: int, max_memory_mb: int,
                 fn: Callable[[ScanTask], dict] = scan_repo,
                 staff: tuple[list[str], list[str]] | None = None) -> Iterator[dict]:
    """Yield a result per task. If the OS kills a worker, only the repos in flight at that moment are
    retried one at a time in isolation; the rest of the queue continues in a fresh pool."""
    init_args = (max_memory_mb, staff)
    pending = deque(tasks)
    while pending:
        suspects: list[ScanTask] = []
        with ProcessPoolExecutor(workers, initializer=init_worker, initargs=init_args) as pool:
            inflight = {}
            broken = False
            while (pending or inflight) and not broken:
                while pending and len(inflight) < workers * 2:
                    task = pending.popleft()
                    inflight[pool.submit(fn, task)] = task
                done, _ = wait(inflight, return_when=FIRST_COMPLETED)
                for fut in done:
                    task = inflight.pop(fut)
                    try:
                        result = fut.result()
                    except BrokenProcessPool:
                        suspects.append(task)
                        broken = True
                        continue
                    yield result
            suspects += inflight.values()
        for task in suspects:
            with ProcessPoolExecutor(1, initializer=init_worker, initargs=init_args) as solo:
                try:
                    yield solo.submit(fn, task).result()
                except BrokenProcessPool:
                    yield _killed_result(task)
