"""Retry policy for transient external-call failures (Batch 5; Section 10).

Scope is deliberately narrow — retry ONLY what is safe to retry:

* ``httpx.TransportError`` family (connection errors, timeouts) — the request
  plausibly never reached the peer or failed idempotently;
* :class:`ci_agent.adapters.github_actions.client.GitHubAPIError` whose HTTP
  status is a server-side 5xx (or transport-shaped ``status_code is None``).

NEVER retried (explicit non-goals, tested by inspection in
``tests/unit/test_reliability/test_retry_policies.py``):

* 4xx GitHub responses (client errors — retrying cannot fix them);
* policy/security decisions. A PDP "fail" is a DECISION, not an error; the
  :class:`PolicyDecisionPoint` path is structurally excluded from this
  decorator, and OPA decision payloads (HTTP 200 with a deny decision) never
  raise, hence never retry.
"""

from __future__ import annotations

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from ci_agent.adapters.errors import GitHubAPIError

# Bounded: 3 attempts total, 0.5s -> 1s -> 2s capped exponential backoff.
MAX_ATTEMPTS = 3
BACKOFF_MULTIPLIER_SECONDS = 0.5
BACKOFF_MAX_SECONDS = 5.0


def _is_transient(exception: BaseException) -> bool:
    """True only for transport-level errors and 5xx/transport GitHub errors."""
    if isinstance(exception, httpx.TransportError):
        return True
    if isinstance(exception, GitHubAPIError):
        return exception.status_code is None or exception.status_code >= 500
    return False


retry_transient_external_call = retry(
    retry=retry_if_exception(_is_transient),
    stop=stop_after_attempt(MAX_ATTEMPTS),
    wait=wait_exponential(multiplier=BACKOFF_MULTIPLIER_SECONDS, max=BACKOFF_MAX_SECONDS),
    reraise=True,
)
"""Tenacity decorator for transient external network calls ONLY.

Apply to GitHub REST calls and OPA HTTP transport. NEVER apply to
``PolicyDecisionPoint.evaluate_gate`` (policy decisions are never retried).
"""

__all__ = [
    "BACKOFF_MAX_SECONDS",
    "BACKOFF_MULTIPLIER_SECONDS",
    "MAX_ATTEMPTS",
    "retry_transient_external_call",
]
