"""Report views over the evidence model (Batch 5, Task C).

Three audiences, three deterministic projections of the same evidence:

* :class:`DeveloperReport` — per-stage outcomes + static remediation hints;
* :class:`ManagementReport` — pass/fail, risk tier, lead time, stage
  durations, exception count (0: the MVP surfaces no waivers/exceptions);
* :class:`ComplianceEvidencePackage` — the full dump incl. policy decisions,
  approvals, and the policy version the gates ran under.

All views are plain JSON-serializable pydantic models.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from ci_agent.core.models.common import RiskTier
from ci_agent.core.models.evidence_model import EvidenceModel
from ci_agent.db.models import PolicyDecisionRecord, RunRecord, StageExecutionRecord

# Static remediation hints per failing stage (developer view). Deliberately a
# plain lookup table — no AI/LLM anywhere (standing constraint).
REMEDIATION_HINTS: dict[str, str] = {
    "checkout": "Check that the source commit exists and the runner has read "
    "access to the repository; inspect the checkout step log.",
    "format_lint": "Fix the lint violations listed in the stage log "
    "(run the linter locally with the pinned config).",
    "sast": "Review the static-analysis findings in the stage log; fix or "
    "triage each issue before re-running.",
    "unit_tests": "Reproduce the failing tests locally with the pinned test "
    "runner; fix code or tests, never skip tests to go green.",
    "secret_scan": "A secret was detected: remove it from the source AND "
    "rotate the credential immediately; then re-run.",
    "dependency_scan": "Upgrade the flagged dependencies to patched versions "
    "(see the scanner report in the stage log).",
}
UNKNOWN_STAGE_HINT = "Inspect the stage log referenced by logs_ref."


class StageReportRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage_id: str
    status: str
    exit_code: int | None
    duration_ms: int | None
    logs_ref: str | None
    remediation_hint: str


class DeveloperReport(BaseModel):
    """Per-stage view for the engineer who owns the change."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    state: str
    stages: list[StageReportRow]
    findings_count: int
    generated_at: datetime


class ManagementReport(BaseModel):
    """Pass/fail + flow metrics for managers (Section 14 reporting)."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    outcome: str  # "pass" | "fail" | "awaiting_approval"
    risk_tier: str
    lead_time_ms: int | None  # trigger received -> last stage completed
    stage_durations_ms: dict[str, int | None]
    policy_exceptions_count: int = 0  # MVP surfaces no waivers/exceptions
    generated_at: datetime


class ComplianceEvidencePackage(BaseModel):
    """Full evidence dump for auditors (Section 4.1 bullet 4)."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    policy_version: str
    evidence: EvidenceModel
    policy_decisions: list[dict[str, Any]]
    approvals: list[dict[str, Any]]
    audit_entries: list[dict[str, Any]]
    stage_records: list[dict[str, Any]]
    generated_at: datetime


def build_developer_report(
    run: RunRecord,
    stages: list[StageExecutionRecord],
    findings_count: int,
) -> DeveloperReport:
    rows = [
        StageReportRow(
            stage_id=record.stage_id,
            status=record.status,
            exit_code=record.exit_code,
            duration_ms=record.duration_ms,
            logs_ref=record.logs_ref,
            remediation_hint=(
                REMEDIATION_HINTS.get(record.stage_id, UNKNOWN_STAGE_HINT)
                if record.status == "failed"
                else ""
            ),
        )
        for record in stages
    ]
    return DeveloperReport(
        run_id=run.run_id,
        state=run.current_state or "unknown",
        stages=rows,
        findings_count=findings_count,
        generated_at=datetime.now(tz=run.created_at.tzinfo) if run.created_at else datetime.now(),
    )


def build_management_report(
    run: RunRecord,
    stages: list[StageExecutionRecord],
    risk_tier: RiskTier | str,
) -> ManagementReport:
    state = run.current_state or ""
    if state in ("merge_decision_published", "approved"):
        outcome = "pass"
    elif state in ("failed", "error", "rejected"):
        outcome = "fail"
    elif state == "awaiting_approval":
        outcome = "awaiting_approval"
    else:
        outcome = "in_progress"
    durations = {record.stage_id: record.duration_ms for record in stages}
    lead_time_ms = None
    completed = [record.completed_at for record in stages if record.completed_at]
    if run.created_at and completed:
        lead_time_ms = int((max(completed) - run.created_at).total_seconds() * 1000)
    tier = risk_tier.value if isinstance(risk_tier, RiskTier) else str(risk_tier)
    return ManagementReport(
        run_id=run.run_id,
        outcome=outcome,
        risk_tier=tier,
        lead_time_ms=lead_time_ms,
        stage_durations_ms=durations,
        policy_exceptions_count=0,
        generated_at=datetime.now(),
    )


def build_compliance_package(
    run: RunRecord,
    evidence: EvidenceModel,
    policy_decisions: list[PolicyDecisionRecord],
    approvals: list[dict[str, Any]],
    audit_entries: list[dict[str, Any]],
    stages: list[StageExecutionRecord],
    policy_version: str,
) -> ComplianceEvidencePackage:
    def _stage_row(record: StageExecutionRecord) -> dict[str, Any]:
        return {
            "stage_id": record.stage_id,
            "status": record.status,
            "exit_code": record.exit_code,
            "started_at": record.started_at.isoformat() if record.started_at else None,
            "completed_at": record.completed_at.isoformat() if record.completed_at else None,
            "duration_ms": record.duration_ms,
            "logs_ref": record.logs_ref,
        }

    def _decision_row(record: PolicyDecisionRecord) -> dict[str, Any]:
        return {
            "stage_id": record.stage_id,
            "decision": record.decision,
            "policy_family": record.policy_family,
            "policy_version": record.policy_version,
            "reasons": json.loads(record.reasons_json) if record.reasons_json else [],
            # Batch 7 (Section 9): waiver ID and grantor visibility — a WAIVED
            # decision is never collapsed into a generic pass.
            "exception_ids": (
                json.loads(record.exception_ids_json) if record.exception_ids_json else []
            ),
            "evaluated_at": record.evaluated_at.isoformat() if record.evaluated_at else None,
        }

    return ComplianceEvidencePackage(
        run_id=run.run_id,
        policy_version=policy_version,
        evidence=evidence,
        policy_decisions=[_decision_row(record) for record in policy_decisions],
        approvals=approvals,
        audit_entries=list(audit_entries),
        stage_records=[_stage_row(record) for record in stages],
        generated_at=datetime.now(),
    )


__all__ = [
    "REMEDIATION_HINTS",
    "UNKNOWN_STAGE_HINT",
    "ComplianceEvidencePackage",
    "DeveloperReport",
    "ManagementReport",
    "StageReportRow",
    "build_compliance_package",
    "build_developer_report",
    "build_management_report",
]
