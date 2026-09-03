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
from ci_agent.core.models.evidence_model import ArtifactRef, EvidenceModel, Finding
from ci_agent.db.models import (
    ApprovalRecord,
    ArtifactRecord,
    FindingRecord,
    PolicyDecisionRecord,
    ProvenanceRecordRow,
    RunRecord,
    SignatureRecordRow,
    StageExecutionRecord,
)


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

        # REAL parsed findings (Batch 6): from FindingRecord rows — the
        # exit-code-only HIGH placeholder is fully removed.
        finding_rows = (
            self._session_factory()
            .execute(
                select(FindingRecord)
                .where(FindingRecord.run_id == run_id)
                .order_by(FindingRecord.id)
            )
            .scalars()
            .all()
        )
        findings = [
            Finding(
                severity=Severity(row.severity),
                scanner=row.scanner,
                rule_id=row.rule_id,
                component=row.component,
                disposition=row.disposition,
            )
            for row in finding_rows
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

        # Batch 7 (Section 8): REAL supply-chain artifacts — digest-based
        # identity (never a tag), with SBOM/signature references as recorded.
        # This is the field empty since Batch 1; populated for real now.
        artifact_rows = (
            self._session_factory()
            .execute(
                select(ArtifactRecord)
                .where(ArtifactRecord.run_id == run_id)
                .order_by(ArtifactRecord.id)
            )
            .scalars()
            .all()
        )
        artifacts = [
            ArtifactRef(
                digest=row.digest,
                registry=row.registry_host,
                sbom_ref=row.sbom_ref,
                signature_ref=row.signature_ref,
            )
            for row in artifact_rows
        ]
        # Attestations (Section 8 rows — empty since Batch 1, populated for
        # real now): cosign signature references + in-toto/SLSA provenance
        # attestations, each a verifiable pointer with its integrity hash —
        # never key material, never raw payloads.
        signature_rows = (
            self._session_factory()
            .execute(
                select(SignatureRecordRow)
                .where(SignatureRecordRow.run_id == run_id)
                .order_by(SignatureRecordRow.id)
            )
            .scalars()
            .all()
        )
        provenance_rows = (
            self._session_factory()
            .execute(
                select(ProvenanceRecordRow)
                .where(ProvenanceRecordRow.run_id == run_id)
                .order_by(ProvenanceRecordRow.id)
            )
            .scalars()
            .all()
        )
        attestations = [f"cosign-signature:{row.signature_ref}" for row in signature_rows]
        attestations.extend(
            f"{row.predicate_type}:{row.attestation_ref}" for row in provenance_rows
        )

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
            artifacts=artifacts,  # Batch 7: real digest-identified artifacts
            attestations=attestations,  # Batch 7: signature + provenance refs
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

    def finding_records(self, run_id: str) -> list[FindingRecord]:
        """Persisted normalized findings for the run (Batch 6)."""
        return list(
            self._session_factory()
            .execute(
                select(FindingRecord)
                .where(FindingRecord.run_id == run_id)
                .order_by(FindingRecord.id)
            )
            .scalars()
            .all()
        )

    def findings_summary(self, run_id: str) -> dict[Severity, int]:
        """Findings count per governed severity (report view summary)."""
        counter: dict[Severity, int] = {}
        for row in self.finding_records(run_id):
            severity = Severity(row.severity)
            counter[severity] = counter.get(severity, 0) + 1
        return counter

    def security_evidence_warnings(self, run_id: str) -> list[dict[str, object]]:
        """Parser-warning incidents for the run (fail-closed visibility)."""
        warnings: list[dict[str, object]] = []
        with self._session_factory() as session:
            rows = (
                session.execute(
                    select(StageExecutionRecord).where(
                        StageExecutionRecord.run_id == run_id,
                        StageExecutionRecord.findings_ref.is_not(None),
                    )
                )
                .scalars()
                .all()
            )
        for row in rows:
            if not row.findings_ref:
                continue
            summary = json.loads(row.findings_ref)
            if summary.get("parser_warnings"):
                warnings.append({"stage_id": row.stage_id, "warnings": summary["parser_warnings"]})
        return warnings

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
