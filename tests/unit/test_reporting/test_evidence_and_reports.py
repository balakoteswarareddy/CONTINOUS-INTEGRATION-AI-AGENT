"""Evidence assembler + report views tests (Batch 5, Task C)."""

from __future__ import annotations

import json

import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.db.models import (
    PolicyDecisionRecord,
    RunRecord,
    utcnow,
)
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.reporting.evidence_assembler import EvidenceAssembler, RunNotFoundError
from ci_agent.reporting.report_models import (
    build_compliance_package,
    build_developer_report,
    build_management_report,
)


@pytest.fixture()
def assembler(session_factory, audit_store: AuditStore) -> EvidenceAssembler:
    return EvidenceAssembler(session_factory, audit_store)


@pytest.fixture()
def failed_run(session_factory, audit_store: AuditStore, observer: ExecutionObserver) -> str:
    """A run whose secret_scan stage failed."""
    audit_store.create_run(
        run_id="run-ev-1",
        project_id="example-org/payments-api",
        repository="example-org/payments-api",
        trigger_type="push",
        source_sha="cafe1234",
    )
    observer.record_stage_transition("run-ev-1", "checkout", StageStatus.PASSED, exit_code=0)
    observer.record_stage_transition("run-ev-1", "secret_scan", StageStatus.FAILED, exit_code=1)
    audit_store.append_event("run-ev-1", "run_state_transition", {"from": None, "to": "failed"})
    return "run-ev-1"


@pytest.fixture()
def observer(session_factory, audit_store: AuditStore) -> ExecutionObserver:
    return ExecutionObserver(session_factory, audit_store)


def test_evidence_model_from_tables(assembler: EvidenceAssembler, failed_run: str) -> None:
    evidence = assembler.assemble_evidence(failed_run)
    assert evidence.run_id == failed_run
    assert evidence.source_commit == "cafe1234"
    # Exit-code-only finding for the failed stage (MVP; Batch 6 enriches).
    assert len(evidence.findings) == 1
    finding = evidence.findings[0]
    assert finding.severity.value == "high"
    assert finding.component == "secret_scan"
    # Unpopulated fields are EMPTY, never omitted.
    assert evidence.artifacts == []
    assert evidence.attestations == []
    assert evidence.approvals == []
    assert evidence.tool_versions == {}
    model_dump = evidence.model_dump(mode="json")
    assert json.dumps(model_dump)  # JSON-serializable


def test_evidence_includes_approvals(
    session_factory, assembler: EvidenceAssembler, failed_run: str
) -> None:
    from ci_agent.db.models import ApprovalRecord

    with session_factory() as session:
        session.add(
            ApprovalRecord(run_id=failed_run, decision="approved", approver="alice", comment=None)
        )
        session.commit()
    evidence = assembler.assemble_evidence(failed_run)
    assert len(evidence.approvals) == 1
    assert evidence.approvals[0].approver == "alice"


def test_evidence_missing_run_raises(assembler: EvidenceAssembler) -> None:
    with pytest.raises(RunNotFoundError):
        assembler.assemble_evidence("ghost-run")


def test_policy_decisions_and_audit_entries(
    session_factory, assembler: EvidenceAssembler, audit_store: AuditStore, failed_run: str
) -> None:
    with session_factory() as session:
        session.add(
            PolicyDecisionRecord(
                run_id=failed_run,
                stage_id="policy_gate",
                decision="fail",
                policy_family="aggregated",
                policy_version="1.0.0",
                reasons_json=json.dumps(["security_policy: high severity finding"]),
            )
        )
        session.commit()
    decisions = assembler.policy_decisions(failed_run)
    assert len(decisions) == 1
    assert decisions[0].decision == "fail"
    entries = assembler.audit_entries(failed_run)
    assert any(entry["event_type"] == "run_state_transition" for entry in entries)
    assert any(entry["event_type"] == "stage_transition" for entry in entries)


def test_developer_report_view(
    session_factory, assembler: EvidenceAssembler, failed_run: str
) -> None:
    with session_factory() as session:
        run = session.get(RunRecord, failed_run)
        run.current_state = "failed"
        session.commit()
    stages = assembler.stage_records(failed_run)
    evidence = assembler.assemble_evidence(failed_run)
    report = build_developer_report(
        assembler._require_run(failed_run), stages, len(evidence.findings)
    )
    data = report.model_dump(mode="json")
    assert data["state"] == "failed"
    secret_rows = [s for s in data["stages"] if s["stage_id"] == "secret_scan"]
    assert secret_rows[0]["exit_code"] == 1
    assert "rotate" in secret_rows[0]["remediation_hint"]
    checkout_rows = [s for s in data["stages"] if s["stage_id"] == "checkout"]
    assert checkout_rows[0]["remediation_hint"] == ""  # passed: no hint
    json.dumps(data)  # serializable


def test_management_report_view(
    session_factory, assembler: EvidenceAssembler, failed_run: str
) -> None:
    with session_factory() as session:
        run = session.get(RunRecord, failed_run)
        run.current_state = "failed"
        session.commit()
    report = build_management_report(
        assembler._require_run(failed_run),
        assembler.stage_records(failed_run),
        "high",
    )
    data = report.model_dump(mode="json")
    assert data["outcome"] == "fail"
    assert data["risk_tier"] == "high"
    assert data["policy_exceptions_count"] == 0
    assert "secret_scan" in data["stage_durations_ms"]
    json.dumps(data)


def test_management_report_pass_and_awaiting(
    session_factory, assembler: EvidenceAssembler, failed_run: str
) -> None:
    run = assembler._require_run(failed_run)
    for state, expected in (
        ("merge_decision_published", "pass"),
        ("awaiting_approval", "awaiting_approval"),
        ("error", "fail"),
    ):
        run.current_state = state
        report = build_management_report(run, [], "low")
        assert report.outcome == expected


def test_compliance_package_view(
    session_factory, assembler: EvidenceAssembler, audit_store: AuditStore, failed_run: str
) -> None:
    with session_factory() as session:
        run = session.get(RunRecord, failed_run)
        run.current_state = "merge_decision_published"
        session.commit()
    package = build_compliance_package(
        assembler._require_run(failed_run),
        evidence=assembler.assemble_evidence(failed_run),
        policy_decisions=assembler.policy_decisions(failed_run),
        approvals=[
            {
                "approver": "alice",
                "decision": "approved",
                "comment": None,
                "created_at": utcnow().isoformat(),
            }
        ],
        audit_entries=assembler.audit_entries(failed_run),
        stages=assembler.stage_records(failed_run),
        policy_version="1.0.0",
    )
    data = package.model_dump(mode="json")
    assert data["policy_version"] == "1.0.0"
    assert data["evidence"]["run_id"] == failed_run
    assert len(data["approvals"]) == 1
    assert data["audit_entries"], "audit trail included verbatim"
    assert any(s["stage_id"] == "secret_scan" for s in data["stage_records"])
    json.dumps(data)  # fully serializable
