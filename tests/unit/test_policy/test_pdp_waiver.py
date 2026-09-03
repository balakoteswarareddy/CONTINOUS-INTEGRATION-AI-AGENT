"""PDP exception-waiver wiring tests (Batch 7, Task D; Sections 6, 9, 18).

Live-OPA tests: a security_policy FAIL converts to WAIVED only when a
governed, non-expired, scope-matching exception exists; the exception ids
land in the audit event AND the PolicyDecisionRecord. Expired, revoked,
non-matching-scope and partially-covering exceptions still FAIL.
"""

from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.exceptions.exception_service import ExceptionService
from ci_agent.exceptions.models import utcnow
from ci_agent.governance import load_policy_spec
from ci_agent.policy.models import PolicyInputFacts
from ci_agent.policy.opa_client import OPAClient
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint

PROJECT = "example-org/payments-api"


def _opa_up() -> bool:
    try:
        response = httpx.get("http://127.0.0.1:8181/health", timeout=2.0)
        return response.status_code == 200
    except httpx.TransportError:
        return False


requires_opa = pytest.mark.skipif(not _opa_up(), reason="requires live OPA")


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'waive.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    audit_store.create_run(
        run_id="run-waive-1",
        project_id=PROJECT,
        repository=PROJECT,
        trigger_type="push",
        source_sha="cafe1234",
    )
    policy_spec = load_policy_spec()
    exceptions = ExceptionService(session_factory, audit_store)
    pdp = PolicyDecisionPoint(
        OPAClient("http://127.0.0.1:8181", 2.0),
        audit_store,
        policy_spec,
        session_factory=session_factory,
        exception_service=exceptions,
    )
    return audit_store, session_factory, pdp, exceptions


def _facts(rule_id: str, run_id: str = "run-waive-1") -> PolicyInputFacts:
    return PolicyInputFacts(
        project_profile={"risk_tier": "low"},
        pipeline_spec={"project_id": PROJECT},
        stage_id="security_gate",
        findings=[
            {
                "severity": "high",
                "scanner": "trivy",
                "rule_id": rule_id,
                "component": "libssl3@3.0.11",
                "disposition": "open",
            }
        ],
        run_id=run_id,
    )


@requires_opa
def test_failing_gate_fails_without_exception(env) -> None:
    _, _, pdp, _ = env
    result = pdp.evaluate_gate("security_gate", _facts("CVE-2023-0286"))
    assert result.decision is PolicyDecision.FAIL
    assert result.exception_ids == []


@requires_opa
def test_active_matching_exception_waives_with_ids_recorded(env) -> None:
    audit_store, session_factory, pdp, exceptions = env
    record = exceptions.grant_exception(
        project_id=PROJECT,
        policy_family="security_policy",
        rule_id="CVE-2023-0286",
        reason="fix landing next sprint",
        granted_by="security-lead",
        expires_at=utcnow() + timedelta(days=7),
    )
    result = pdp.evaluate_gate("security_gate", _facts("CVE-2023-0286"))
    assert result.decision is PolicyDecision.WAIVED
    assert result.exception_ids == [record.id]

    # The exception id is recorded on the decision row (Section 9 visibility).
    from ci_agent.db.models import PolicyDecisionRecord

    with session_factory() as session:
        row = (
            session.query(PolicyDecisionRecord)
            .filter_by(run_id="run-waive-1", stage_id="security_gate")
            .order_by(PolicyDecisionRecord.id.desc())
            .first()
        )
        assert row is not None
        assert row.decision == "waived"
        assert json.loads(row.exception_ids_json or "[]") == [record.id]
    # ...and in the audit event.
    payloads = [
        json.loads(e.payload_json)
        for e in audit_store.get_audit_trail("run-waive-1")
        if e.event_type == "policy_decision"
    ]
    assert payloads[-1]["exception_ids"] == [record.id]


@requires_opa
def test_expired_exception_still_fails(env, monkeypatch) -> None:
    _, _, pdp, exceptions = env
    from ci_agent.exceptions import exception_service as exc_module

    base = utcnow()
    monkeypatch.setattr(exc_module, "utcnow", lambda: base)
    exceptions.grant_exception(
        project_id=PROJECT,
        policy_family="security_policy",
        rule_id="CVE-2023-0286",
        reason="about to die",
        granted_by="security-lead",
        expires_at=base + timedelta(microseconds=1),
    )
    # One microsecond later the exception is dead — the gate FAILS again.
    monkeypatch.setattr(exc_module, "utcnow", lambda: base + timedelta(seconds=1))
    result = pdp.evaluate_gate("security_gate", _facts("CVE-2023-0286"))
    assert result.decision is PolicyDecision.FAIL


@requires_opa
def test_revoked_exception_still_fails(env) -> None:
    _, _, pdp, exceptions = env
    record = exceptions.grant_exception(
        project_id=PROJECT,
        policy_family="security_policy",
        rule_id="CVE-2023-0286",
        reason="revoked quickly",
        granted_by="security-lead",
        expires_at=utcnow() + timedelta(days=7),
    )
    exceptions.revoke_exception(record.id, revoked_by="security-council")
    result = pdp.evaluate_gate("security_gate", _facts("CVE-2023-0286"))
    assert result.decision is PolicyDecision.FAIL


@requires_opa
def test_non_matching_project_scope_still_fails(env) -> None:
    """Task E scenario: an exception exists but does not cover THIS project."""
    _, _, pdp, exceptions = env
    exceptions.grant_exception(
        project_id="other-org/other-repo",
        policy_family="security_policy",
        rule_id=None,
        reason="family-wide for a different project",
        granted_by="security-lead",
        expires_at=utcnow() + timedelta(days=30),
    )
    result = pdp.evaluate_gate("security_gate", _facts("CVE-2023-0286"))
    assert result.decision is PolicyDecision.FAIL


@requires_opa
def test_rule_scoped_exception_does_not_cover_other_rules(env) -> None:
    _, _, pdp, exceptions = env
    exceptions.grant_exception(
        project_id=PROJECT,
        policy_family="security_policy",
        rule_id="CVE-SOMETHING-ELSE",
        reason="covers a different rule",
        granted_by="security-lead",
        expires_at=utcnow() + timedelta(days=7),
    )
    result = pdp.evaluate_gate("security_gate", _facts("CVE-2023-0286"))
    assert result.decision is PolicyDecision.FAIL


@requires_opa
def test_partial_coverage_still_fails_conservatively(env) -> None:
    """Two failing rules; only one covered -> still FAIL (no partial waiver)."""
    _, _, pdp, exceptions = env
    exceptions.grant_exception(
        project_id=PROJECT,
        policy_family="security_policy",
        rule_id="CVE-COVERED",
        reason="the only covered rule",
        granted_by="security-lead",
        expires_at=utcnow() + timedelta(days=7),
    )
    facts = PolicyInputFacts(
        project_profile={"risk_tier": "low"},
        pipeline_spec={"project_id": PROJECT},
        stage_id="security_gate",
        findings=[
            {
                "severity": "high",
                "scanner": "trivy",
                "rule_id": "CVE-COVERED",
                "component": "a",
                "disposition": "open",
            },
            {
                "severity": "critical",
                "scanner": "trivy",
                "rule_id": "CVE-UNCOVERED",
                "component": "b",
                "disposition": "open",
            },
        ],
        run_id="run-waive-1",
    )
    result = pdp.evaluate_gate("security_gate", facts)
    assert result.decision is PolicyDecision.FAIL
