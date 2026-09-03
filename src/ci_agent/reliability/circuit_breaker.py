"""Hand-rolled circuit breaker for external calls (Batch 5; Section 11).

Deliberately NOT the ``pybreaker`` dependency: the needed semantics (closed ->
open after N consecutive failures -> half-open after a cooldown -> probe) are
~80 lines, and owning them keeps the dependency footprint minimal and the
behaviour explicit/testable. Choice documented in NOTES.md.

An OPEN breaker protecting the OPA client raises
:class:`ci_agent.policy.opa_client.OPAUnavailableError`, which the PDP's
documented fail-closed path turns into an overall "fail" decision — an open
breaker can never silently become an implicit policy pass.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

T = TypeVar("T")

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


class BreakerOpenError(RuntimeError):
    """The circuit is open; the call was not attempted."""

    def __init__(self, name: str, retry_after_seconds: float) -> None:
        self.name = name
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"circuit breaker {name!r} is open; retry allowed in " f"{retry_after_seconds:.1f}s"
        )


@dataclass
class CircuitBreaker:
    """Closed/open/half-open breaker keyed to one protected dependency."""

    name: str
    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    state: str = CLOSED
    consecutive_failures: int = 0
    opened_at: float | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def call(self, operation: Callable[[], T]) -> T:
        """Run ``operation`` under breaker discipline."""
        with self._lock:
            if self.state is OPEN:
                elapsed = time.monotonic() - (self.opened_at or 0.0)
                if elapsed < self.recovery_timeout_seconds:
                    raise BreakerOpenError(self.name, self.recovery_timeout_seconds - elapsed)
                # Cooldown elapsed: allow ONE probe through (half-open).
                self.state = HALF_OPEN
        try:
            result = operation()
        except Exception:
            self._record_failure()
            raise
        self._record_success()
        return result

    # ------------------------------------------------------------- internals

    def _record_success(self) -> None:
        with self._lock:
            self.consecutive_failures = 0
            self.state = CLOSED
            self.opened_at = None

    def _record_failure(self) -> None:
        with self._lock:
            self.consecutive_failures += 1
            if self.state is HALF_OPEN or (
                self.state is CLOSED and self.consecutive_failures >= self.failure_threshold
            ):
                self.state = OPEN
                self.opened_at = time.monotonic()

    # ----------------------------------------------------------- inspection

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "name": self.name,
                "state": self.state,
                "consecutive_failures": self.consecutive_failures,
            }


__all__ = [
    "CLOSED",
    "HALF_OPEN",
    "OPEN",
    "BreakerOpenError",
    "CircuitBreaker",
]
