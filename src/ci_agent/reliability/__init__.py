"""Reliability controls (Batch 5; Report Sections 10, 11).

* ``retry_transient_external_call`` — bounded retry with exponential backoff
  for TRANSIENT failures of EXTERNAL network calls (GitHub REST, OPA HTTP).
  NEVER applied to policy/security decisions: a deny is a decision, not a
  failure, and re-evaluating it would be an integrity violation (Section 10).
* :class:`ci_agent.reliability.circuit_breaker.CircuitBreaker` — hand-rolled
  breaker (closed/open/half-open) protecting OPA and GitHub calls; an open OPA
  breaker surfaces as :class:`OPAUnavailableError` so the PDP's documented
  fail-closed behaviour is preserved.
* :class:`ci_agent.reliability.concurrency_guard.ConcurrencyGuard` — in-process
  per-project in-flight quota (backpressure before dispatch).
* ``backup_notes.md`` — honest operational documentation of what is and is not
  implemented for backups/recovery.
"""

from ci_agent.reliability.circuit_breaker import BreakerOpenError, CircuitBreaker
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard
from ci_agent.reliability.retry_policies import retry_transient_external_call

__all__ = [
    "BreakerOpenError",
    "CircuitBreaker",
    "ConcurrencyGuard",
    "retry_transient_external_call",
]
