"""Exception/waiver workflow tests (Batch 7, Task D; Sections 6, 7.3, 18).

Guardrails under test:
* expires_at is REQUIRED — a permanent exception cannot exist;
* expiry is derived from the clock (no manual job needed for correctness);
* the ONLY creation path is ExceptionService.grant_exception — the PDP,
  Planner and orchestrators have NO write path (Section 7.3 "Policy bypass";
  enforced by inspection tests below).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.exceptions import exception_service as exception_service_module
from ci_agent.exceptions.exception_service import ExceptionService
from ci_agent.exceptions.models import ExceptionStatus, utcnow

SRC = Path(__file__).resolve().parents[3] / "src" / "ci_agent"
LATER = utcnow() + timedelta(days=7)


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'exc.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    return session_factory, audit_store, ExceptionService(session_factory, audit_store)


def _grant(service: ExceptionService, **overrides):
    payload: dict = {
        "project_id": "example-org/payments-api",
        "policy_family": "security_policy",
        "rule_id": "CVE-2023-0286",
        "reason": "fix scheduled for next sprint",
        "granted_by": "security-lead",
        "expires_at": LATER,
    }
    payload.update(overrides)
    return service.grant_exception(**payload)


class TestGrantLifecycle:
    def test_grant_persists_and_is_retrievable(self, env) -> None:
        _, _, service = env
        record = _grant(service)
        assert record.id.startswith("exc-")
        assert record.status is ExceptionStatus.ACTIVE
        fetched = service.get_record(record.id)
        assert fetched.expires_at == record.expires_at
        assert fetched.reason == "fix scheduled for next sprint"

    def test_grant_is_audited(self, env) -> None:
        _, audit_store, service = env
        record = _grant(service)
        events = {
            e.event_type: json.loads(e.payload_json)
            for e in audit_store.get_audit_trail("exception")
        }
        assert events["exception_granted"]["exception_id"] == record.id
        assert events["exception_granted"]["granted_by"] == "security-lead"
        assert events["exception_granted"]["policy_family"] == "security_policy"

    def test_null_expiry_rejected(self, env) -> None:
        _, _, service = env
        with pytest.raises(ValueError, match="expires_at is REQUIRED"):
            service.grant_exception(
                project_id="p",
                policy_family="security_policy",
                reason="r",
                granted_by="g",
                expires_at=None,  # type: ignore[arg-type]
            )

    def test_past_expiry_rejected(self, env) -> None:
        _, _, service = env
        with pytest.raises(ValueError, match="expires_at"):
            _grant(service, expires_at=utcnow() - timedelta(days=1))

    def test_revoke(self, env) -> None:
        _, audit_store, service = env
        record = _grant(service)
        revoked = service.revoke_exception(record.id, revoked_by="security-council")
        assert revoked.status is ExceptionStatus.REVOKED
        assert revoked.revoked_by == "security-council"
        assert service.get_active_exceptions("example-org/payments-api") == []
        events = {e.event_type for e in audit_store.get_audit_trail("exception")}
        assert "exception_revoked" in events

    def test_unknown_exception_revocation_is_loud(self, env) -> None:
        _, _, service = env
        with pytest.raises(LookupError):
            service.revoke_exception("exc-does-not-exist", revoked_by="someone")


class TestExpiryIsAutomatic:
    def test_expired_exception_inactive_without_manual_job(self, env, monkeypatch) -> None:
        """Section 18: expiry derives from the clock at read time."""
        _, _, service = env
        real_utcnow = exception_service_module.utcnow
        virtual_now = datetime(2026, 9, 1, 0, 0, 0)

        def fake_utcnow() -> datetime:
            return virtual_now

        monkeypatch.setattr(exception_service_module, "utcnow", fake_utcnow)
        record = service.grant_exception(
            project_id="p",
            policy_family="security_policy",
            rule_id=None,
            reason="temporary",
            granted_by="security-lead",
            expires_at=virtual_now + timedelta(hours=1),
        )
        assert service.find_covering_exception("p", "security_policy", "any-rule") is not None

        # Two hours pass. NO cleanup job runs — the exception is simply dead.
        monkeypatch.setattr(
            exception_service_module,
            "utcnow",
            lambda: virtual_now + timedelta(hours=2),
        )
        assert service.find_covering_exception("p", "security_policy", "any-rule") is None
        assert service.get_active_exceptions("p") == []

        # The hygiene job flips stored status (correctness never depends on it).
        monkeypatch.setattr(exception_service_module, "utcnow", real_utcnow)
        assert service.expire_due_exceptions() == 1
        assert service.get_record(record.id).status is ExceptionStatus.EXPIRED


class TestScoping:
    def test_family_and_project_scope(self, env) -> None:
        _, _, service = env
        _grant(service, rule_id=None)  # family-wide
        assert (
            service.find_covering_exception(
                "example-org/payments-api", "security_policy", "any-rule"
            )
            is not None
        )
        assert service.find_covering_exception("other/project", "security_policy", None) is None
        assert (
            service.find_covering_exception("example-org/payments-api", "artifact_policy", None)
            is None
        )

    def test_rule_scoped_does_not_cover_other_rules(self, env) -> None:
        _, _, service = env
        _grant(service, rule_id="CVE-2023-0286")
        assert (
            service.find_covering_exception(
                "example-org/payments-api", "security_policy", "CVE-2023-0286"
            )
            is not None
        )
        assert (
            service.find_covering_exception(
                "example-org/payments-api", "security_policy", "CVE-OTHER"
            )
            is None
        )


class TestNoAutoGrantInspection:
    """Section 7.3 "Policy bypass" — enforced by inspection of the source.

    Direct ORM construction of exception rows may appear ONLY in
    ExceptionService; the PDP, Planner and orchestrators may not even
    mention the write path.
    """

    def test_direct_orm_construction_only_in_the_service(self) -> None:
        writers = {
            path
            for path in SRC.rglob("*.py")
            if "ExceptionRecordRow(" in path.read_text(encoding="utf-8")
        }
        assert writers == {SRC / "exceptions" / "exception_service.py"}

    def test_pdp_has_no_exception_write_path(self) -> None:
        pdp = (SRC / "policy" / "policy_decision_point.py").read_text(encoding="utf-8")
        assert "find_covering_exception" in pdp  # read side IS wired
        for forbidden in ("grant_exception", "revoke_exception", "ExceptionRecordRow"):
            assert forbidden not in pdp, f"PDP must never {forbidden}"

    def test_planner_and_orchestrators_have_no_exception_write_path(self) -> None:
        for name in (
            "planner/planner.py",
            "orchestrator/phase_a_orchestrator.py",
            "orchestrator/phase_b_orchestrator.py",
        ):
            text = (SRC / name).read_text(encoding="utf-8")
            for forbidden in ("grant_exception", "ExceptionRecordRow", "exception_records"):
                assert forbidden not in text, f"{name} must never reference {forbidden}"
