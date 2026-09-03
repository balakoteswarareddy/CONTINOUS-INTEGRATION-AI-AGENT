"""Per-project in-flight run quota (Batch 5; Section 10 concurrency limits).

MVP: an in-process guard (thread-safe counters). Deliberately NOT
cross-process — a multi-replica deployment needs a shared store (Redis or DB
lease rows); that is a documented deferral in NOTES.md. The orchestrator
acquires before dispatch and releases when a run reaches a terminal state or
on any dispatch failure (no quota leaks).
"""

from __future__ import annotations

import threading


class ConcurrencyGuard:
    """Track and bound in-flight runs per project (in-process)."""

    def __init__(self, max_per_project: int) -> None:
        if max_per_project < 1:
            raise ValueError("max_per_project must be >= 1")
        self._max = max_per_project
        self._in_flight: dict[str, int] = {}
        self._lock = threading.Lock()

    def acquire(self, project_id: str) -> bool:
        """Reserve one in-flight slot; False when the project is at its limit."""
        with self._lock:
            current = self._in_flight.get(project_id, 0)
            if current >= self._max:
                return False
            self._in_flight[project_id] = current + 1
            return True

    def release(self, project_id: str) -> None:
        """Return one slot; releasing an unacquired project is a no-op."""
        with self._lock:
            current = self._in_flight.get(project_id, 0)
            if current <= 1:
                self._in_flight.pop(project_id, None)
            else:
                self._in_flight[project_id] = current - 1

    def in_flight(self, project_id: str) -> int:
        with self._lock:
            return self._in_flight.get(project_id, 0)


__all__ = ["ConcurrencyGuard"]
