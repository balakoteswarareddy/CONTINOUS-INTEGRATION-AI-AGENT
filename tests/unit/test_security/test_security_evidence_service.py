"""Batch 6 Task C: Security Evidence Service — persistence, audit, fail-closed.

Includes the NON-NEGOTIABLE secret-redaction test: the known fixture secret
must never appear in ANY FindingRecord, AuditLogEntry, or stage summary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import Severity, StageStatus
from ci_agent.db.models import FindingRecord, StageExecutionRecord
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.security import UnknownParserError
from ci_agent.security.security_evidence_service import SecurityEvidenceService
from ci_agent.security.severity_mapping import UnknownSeverityError

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "security_tool_outputs"
SECRET = "AKIAIOSFODNN7EXAMPLE-REDACTED-TEST-VALUE"


@pytest.fixture()
def service(session_factory, audit_store: AuditStore) -> SecurityEvidenceService:
    return SecurityEvidenceService(session_factory, audit_store)


@pytest.fixture()
def observed_stage(session_factory, audit_store: AuditStore) -> None:
    """Create the sast stage row so the summary has a place to attach."""
    ExecutionObserver(session_factory, audit_store).record_stage_transition(
        "run-sec-1", "sast", StageStatus.RUNNING
    )
    audit_store.create_run(
        run_id="run-sec-1",
        project_id="example-org/payments-api",
        repository="example-org/payments-api",
        trigger_type="push",
        source_sha="cafe1234",
    )


def test_full_pipeline_bandit_high_finding_collected(
    session_factory, audit_store: AuditStore, service: SecurityEvidenceService, observed_stage
) -> None:
    raw = (FIXTURES / "bandit_with_findings.json").read_text(encoding="utf-8")
    records = service.collect_findings("run-sec-1", "sast", "bandit", raw)

    assert len(records) == 2  # fixture: 1 HIGH (B605) + 1 LOW (B101)
    summary = service.get_findings_summary("run-sec-1")
    assert summary == {Severity.HIGH: 1, Severity.LOW: 1}

    # Audit event carries counts only.
    event = next(
        entry
        for entry in audit_store.get_audit_trail("run-sec-1")
        if entry.event_type == "findings_collected"
    )
    payload = json.loads(event.payload_json)
    assert payload["by_severity"] == {"high": 1, "low": 1}
    assert payload["count"] == 2
    assert payload["stage_id"] == "sast"
    # No raw tool payload in the audit event.
    assert "B605" not in event.payload_json

    # Stage summary attached to the observed stage row.
    with session_factory() as session:
        stage = session.query(StageExecutionRecord).filter_by(stage_id="sast").one()
        blob = json.loads(stage.findings_ref)
        assert blob["count"] == 2
        assert blob["by_severity"] == {"high": 1, "low": 1}
        assert blob["parser_warnings"] == []


def test_clean_scan_records_zero_count_no_warnings(
    session_factory, service: SecurityEvidenceService, observed_stage
) -> None:
    raw = (FIXTURES / "bandit_clean.json").read_text(encoding="utf-8")
    records = service.collect_findings("run-sec-1", "sast", "bandit", raw)
    assert records == []
    assert service.get_findings_summary("run-sec-1") == {}
    with session_factory() as session:
        stage = session.query(StageExecutionRecord).filter_by(stage_id="sast").one()
        assert json.loads(stage.findings_ref)["count"] == 0


def test_unparseable_output_is_flagged_never_clean(
    session_factory, audit_store: AuditStore, service: SecurityEvidenceService, observed_stage
) -> None:
    records = service.collect_findings("run-sec-1", "sast", "bandit", "<<<totally not JSON>>>")
    assert records == []
    assert service.has_parser_warnings("run-sec-1") is True
    flagged = service.parser_warnings("run-sec-1")
    assert flagged == [{"stage_id": "sast", "warnings": flagged[0]["warnings"]}]
    # Audit trail shows the warning too (fail-closed evidence).
    event = next(
        entry
        for entry in audit_store.get_audit_trail("run-sec-1")
        if entry.event_type == "findings_collected"
    )
    assert json.loads(event.payload_json)["parser_warnings"]


def test_unregistered_tool_fails_loudly(service: SecurityEvidenceService, observed_stage) -> None:
    with pytest.raises(UnknownParserError, match="no findings parser registered"):
        service.collect_findings("run-sec-1", "sast", "mystery-scanner", "{}")


def test_gitleaks_secret_value_never_stored_anywhere(
    session_factory, audit_store: AuditStore, service: SecurityEvidenceService
) -> None:
    """THE redaction test: grep-style sweep of every table after processing."""
    ExecutionObserver(session_factory, audit_store).record_stage_transition(
        "run-sec-1", "secret_scan", StageStatus.RUNNING
    )
    raw = (FIXTURES / "gitleaks_with_secret.json").read_text(encoding="utf-8")
    records = service.collect_findings("run-sec-1", "secret_scan", "gitleaks", raw)

    assert len(records) == 1
    assert records[0].severity == "critical"
    assert records[0].rule_id == "aws-access-key-id"

    # 1. Every FindingRecord row.
    with session_factory() as session:
        finding_rows = session.query(FindingRecord).all()
    for row in finding_rows:
        for column_value in (
            row.component,
            row.description,
            row.location,
            row.rule_id,
            row.scanner,
            row.stage_id,
            row.disposition,
        ):
            assert SECRET not in str(column_value)

    # 2. Every audit entry (payload + serialized form) for the run.
    trail = audit_store.get_audit_trail("run-sec-1")
    for entry in trail:
        assert SECRET not in entry.payload_json
        assert "AKIA" not in entry.payload_json

    # 3. Stage summary blobs.
    with session_factory() as session:
        stages = session.query(StageExecutionRecord).all()
    for stage in stages:
        if stage.findings_ref:
            assert SECRET not in stage.findings_ref


def test_findings_summary_distinguishes_empty_vs_missing(
    service: SecurityEvidenceService, observed_stage
) -> None:
    """A run with no collected stages yet -> empty dict (not a clean claim)."""
    assert service.get_findings_summary("run-sec-1") == {}
    assert service.has_parser_warnings("run-sec-1") is False


def test_unknown_severity_never_reaches_storage(
    service: SecurityEvidenceService, observed_stage
) -> None:
    """A bandit report with an unexpected severity word must fail loudly."""
    weird = (
        '{"results": [{"issue_severity": "CATASTROPHIC", "test_id": "B999", '
        '"filename": "x.py", "line_number": 1, '
        '"issue_text": "new bandit version?"}]}'
    )
    with pytest.raises(UnknownSeverityError):
        service.collect_findings("run-sec-1", "sast", "bandit", weird)
    assert service.get_findings_for_run("run-sec-1") == []
