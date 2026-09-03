"""Concurrency guard tests (Batch 5): per-project quota, no leaks."""

from __future__ import annotations

import threading

from ci_agent.reliability.concurrency_guard import ConcurrencyGuard


def test_acquire_within_limit() -> None:
    guard = ConcurrencyGuard(max_per_project=2)
    assert guard.acquire("proj") is True
    assert guard.acquire("proj") is True
    assert guard.in_flight("proj") == 2


def test_acquire_blocked_at_limit() -> None:
    guard = ConcurrencyGuard(max_per_project=1)
    assert guard.acquire("proj") is True
    assert guard.acquire("proj") is False
    assert guard.in_flight("proj") == 1


def test_release_frees_slot() -> None:
    guard = ConcurrencyGuard(max_per_project=1)
    assert guard.acquire("proj") is True
    guard.release("proj")
    assert guard.acquire("proj") is True


def test_projects_are_independent() -> None:
    guard = ConcurrencyGuard(max_per_project=1)
    assert guard.acquire("a") is True
    assert guard.acquire("b") is True
    assert guard.acquire("a") is False


def test_release_of_unknown_project_is_noop() -> None:
    guard = ConcurrencyGuard(max_per_project=1)
    guard.release("ghost")
    assert guard.in_flight("ghost") == 0


def test_threads_never_exceed_limit() -> None:
    guard = ConcurrencyGuard(max_per_project=2)
    acquired: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        if guard.acquire("proj"):
            with lock:
                acquired.append(1)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(acquired) == 2
