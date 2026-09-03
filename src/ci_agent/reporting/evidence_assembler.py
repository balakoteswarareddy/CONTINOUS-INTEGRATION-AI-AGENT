"""Evidence assembly from control-plane tables (Batch 5; Section 4.1 bullet 4).

Pure database projection: run record + stage execution records + hash-chained
audit entries + persisted PDP decisions + approval records -> one
:class:`EvidenceModel`. Fields with no source yet (scanner findings detail,
SBOM/attestations) stay EMPTY — never fabricated, never omitted.
"""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import ApprovalStatus, Severity
from ci_agent.core.models.evidence_model import (
    ApprovalRecord as ApprovalEvidence,
)
from ci_agent.core.models.evidence_model import EvidenceModel, Finding
from ci_agent.db.models import (
    ApprovalRecord,
    PolicyDecisionRecord,
    RunRecord,
    StageExecutionRecord,
)

# Exit-code-only findings (MVP): a failed tool stage becomes one HIGH finding.
EXIT_CODE_FINDING_SEVERITY = Severity.HIGH


class RunNotFoundError(LookupError):
    """Raised when assembling evidence for a run id that does not exist."""


class EvidenceAssembler:
    """Assemble the EvidenceModel for one run from persisted control-plane rows."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        audit_store: AuditStore,
    ) -> None:
        self._session_factory = session_factory
        self._audit_store = audit_store

    def assemble_evidence(self, run_id: str) -> EvidenceModel:
        run = self._require_run(run_id)

        stage_records = (
            self._session_factory()
            .execute(
                select(StageExecutionRecord)
                .where(StageExecutionRecord.run_id == run_id)
                .order_by(StageExecutionRecord.id)
            )
            .scalars()
            .all()
        )
        approval_rows = (
            self._session_factory()
            .execute(
                select(ApprovalRecord)
                .where(ApprovalRecord.run_id == run_id)
                .order_by(ApprovalRecord.id)
            )
            .scalars()
            .all()
        )

        # Exit-code-only findings for failed stages (Batch 6 adds real parsing).
        findings = [
            Finding(
                severity=EXIT_CODE_FINDING_SEVERITY,
                scanner=record.stage_id,
                rule_id="stage_exit_code_nonzero",
                component=record.stage_id,
                disposition="open",
            )
            for record in stage_records
            if record.status == "failed"
        ]

        approvals = [
            ApprovalEvidence(
                approver=row.approver,
                status=(
                    ApprovalStatus.APPROVED
                    if row.decision == "approved"
                    else ApprovalStatus.REJECTED
                ),
                timestamp=row.created_at,
            )
            for row in approval_rows
        ]

        timestamps: dict[str, object] = {}
        if run.created_at:
            timestamps["trigger_received_at"] = run.created_at
        started = [r.started_at for r in stage_records if r.started_at]
        completed = [r.completed_at for r in stage_records if r.completed_at]
        if started:
            timestamps["first_stage_started_at"] = min(started)
        if completed:
            timestamps["last_stage_completed_at"] = max(completed)

        return EvidenceModel(
            run_id=run.run_id,
            source_commit=run.source_sha or "",
            pipeline_hash=run.pipeline_spec_ref or "",
            # Tool versions are not persisted per stage yet (Batch 6 refines);
            # an empty map is an honest "not populated", never a fabrication.
            tool_versions={},
            findings=findings,
            approvals=approvals,
            artifacts=[],  # SBOM/artifact signing arrive with Batch 7
            attestations=[],
            timestamps=timestamps,
        )

    def policy_decisions(self, run_id: str) -> list[PolicyDecisionRecord]:
        """Persisted PDP decisions for the run (fail-closed entries included)."""
        return list(
            self._session_factory()
            .execute(
                select(PolicyDecisionRecord)
                .where(PolicyDecisionRecord.run_id == run_id)
                .order_by(PolicyDecisionRecord.id)
            )
            .scalars()
            .all()
        )

    def stage_records(self, run_id: str) -> list[StageExecutionRecord]:
        return list(
            self._session_factory()
            .execute(
                select(StageExecutionRecord)
                .where(StageExecutionRecord.run_id == run_id)
                .order_by(StageExecutionRecord.id)
            )
            .scalars()
            .all()
        )

    def approval_records(self, run_id: str) -> list[ApprovalRecord]:
        """Persisted approval rows for the run, oldest first."""
        return list(
            self._session_factory()
            .execute(
                select(ApprovalRecord)
                .where(ApprovalRecord.run_id == run_id)
                .order_by(ApprovalRecord.id)
            )
            .scalars()
            .all()
        )

    def audit_entries(self, run_id: str) -> list[dict[str, object]]:
        """Verbatim audit trail entries for the run (hash-chained, AuditStore)."""
        entries = self._audit_store.get_audit_trail(run_id)
        return [
            {
                "id": entry.id,
                "run_id": entry.run_id,
                "event_type": entry.event_type,
                "payload": json.loads(entry.payload_json),
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
                "entry_hash": entry.entry_hash,
                "prev_hash": entry.prev_hash,
            }
            for entry in entries
        ]

    def _require_run(self, run_id: str) -> RunRecord:
        with self._session_factory() as session:
            run = session.get(RunRecord, run_id)
            if run is None:
                raise RunNotFoundError(f"run {run_id!r} does not exist")
            session.expunge(run)
            return run


__all__ = ["EvidenceAssembler", "RunNotFoundError"]
