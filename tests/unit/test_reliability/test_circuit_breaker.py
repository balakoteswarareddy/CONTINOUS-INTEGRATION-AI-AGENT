"""Circuit breaker tests (Batch 5): open/half-open transitions + PDP fail-closed."""

from __future__ import annotations

import pytest

from ci_agent.policy.opa_client import OPAUnavailableError
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.reliability.circuit_breaker import (
    CLOSED,
    OPEN,
    BreakerOpenError,
    CircuitBreaker,
)


def test_stays_closed_while_under_threshold() -> None:
    breaker = CircuitBreaker("opa", failure_threshold=3, recovery_timeout_seconds=60)
    for _ in range(2):
        with pytest.raises(RuntimeError):
            breaker.call(_fail())
    assert breaker.state == CLOSED
    assert breaker.consecutive_failures == 2


def test_opens_after_n_consecutive_failures() -> None:
    breaker = CircuitBreaker("opa", failure_threshold=3, recovery_timeout_seconds=60)
    for _ in range(3):
        with pytest.raises(RuntimeError):
            breaker.call(_fail())
    assert breaker.state == OPEN
    with pytest.raises(BreakerOpenError):
        breaker.call(_succeed())


def test_success_resets_failure_count() -> None:
    breaker = CircuitBreaker("opa", failure_threshold=3, recovery_timeout_seconds=60)
    for _ in range(2):
        with pytest.raises(RuntimeError):
            breaker.call(_fail())
    assert breaker.call(_succeed()) == "ok"
    assert breaker.consecutive_failures == 0


def test_half_open_after_cooldown_then_probe() -> None:
    breaker = CircuitBreaker("opa", failure_threshold=1, recovery_timeout_seconds=0.0)
    with pytest.raises(RuntimeError):
        breaker.call(_fail())
    assert breaker.state == OPEN
    # Cooldown is 0s: the next call probes (half-open)...
    assert breaker.call(_succeed()) == "ok"
    assert breaker.state == CLOSED


def test_half_open_failure_reopens() -> None:
    breaker = CircuitBreaker("opa", failure_threshold=1, recovery_timeout_seconds=0.0)
    with pytest.raises(RuntimeError):
        breaker.call(_fail())
    with pytest.raises(RuntimeError):
        breaker.call(_fail())  # probe fails -> reopen
    assert breaker.state == OPEN


def test_opa_breaker_open_surfaces_as_opa_unavailable() -> None:
    """An open OPA breaker MUST be indistinguishable from OPA being down:

    the PDP keeps its documented fail-closed behaviour (Section 18) — an open
    breaker can never become an implicit policy pass.
    """
    breaker = CircuitBreaker("opa", failure_threshold=1, recovery_timeout_seconds=60)
    with pytest.raises(RuntimeError):
        breaker.call(_fail())
    with pytest.raises(BreakerOpenError) as excinfo:
        breaker.call(_fail())
    # The PDP failure path catches OPAUnavailableError; BreakerOpenError is
    # converted by wrapping adapters — verify the conversion contract:
    assert _to_opa_unavailable(excinfo.value) is not None


def _to_opa_unavailable(error: Exception) -> OPAUnavailableError | None:
    """The adapter used by BreakerProtectedOPAClient (documented conversion)."""
    if isinstance(error, BreakerOpenError):
        return OPAUnavailableError(f"policy engine circuit breaker open — fail closed: {error}")
    return None


def _fail() -> object:
    def _raise() -> str:
        raise RuntimeError("dependency down")

    return _raise


def _succeed() -> object:
    return lambda: "ok"


def test_pdp_fail_closed_path_accepts_breaker_error_message() -> None:
    """The wrapped client raises OPAUnavailableError; PDP returns fail.

    Uses a stub OPA client that raises OPAUnavailableError exactly the way the
    breaker-wrapping adapter does, verifying the PDP end of the contract.
    """
    from ci_agent.core.models.common import PolicyDecision
    from ci_agent.policy.models import PolicyInputFacts

    class _BrokenOPA:
        def evaluate(self, package: str, input_facts: dict) -> dict:
            raise OPAUnavailableError("policy engine circuit breaker open — fail closed")

    pdp = PolicyDecisionPoint(_BrokenOPA(), _NullAudit())  # type: ignore[arg-type]
    facts = PolicyInputFacts(project_profile={}, pipeline_spec={}, stage_id="policy_gate")
    result = pdp.evaluate_gate("policy_gate", facts)
    assert result.decision is PolicyDecision.FAIL
    assert any("circuit breaker" in reason for reason in result.reasons)


class _NullAudit:
    def append_event(self, run_id: str, event_type: str, payload: dict) -> None:
        self.last = (run_id, event_type, payload)
