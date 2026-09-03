"""ORM tables for the audit store (Batch 2, Task A; Report Sections 4.2 and 9).

Three tables:
- ``run_records`` — one row per accepted pipeline run, keyed by the run ID
  issued by the Ingress / Trigger Gateway (Section 4.2).
- ``audit_log_entries`` — append-only, hash-chained audit trail (Section 9
  "Audit trail"); each entry's hash covers the previous entry's hash, giving
  tamper-evidence without an external ledger.
- ``processed_deliveries`` — delivery-ID dedupe backing the replay guard
  (Section 7.3 "State confusion / replay" control).

Datetime convention: all datetimes are stored as naive UTC ("coordinated
universal time without offset marker"). SQLite cannot round-trip timezone
offsets stably and the audit hash chain depends on byte-stable
``created_at.isoformat()`` values, so UTC-by-convention is used throughout the
DB layer (documented in NOTES.md).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ci_agent.db.base import Base

# Application-layer status vocabulary for RunRecord.status (free string column
# per Batch 2 spec; constrained here until the state machine lands).
RUN_STATUS_ACCEPTED: Final[str] = "accepted"

# Marker used as prev_hash for the first audit entry of each run.
GENESIS_PREV_HASH: Final[str] = "GENESIS"


def utcnow() -> datetime:
    """Current UTC time as a naive datetime (see module docstring)."""

    return datetime.now(UTC).replace(tzinfo=None)


class RunRecord(Base):
    """One accepted pipeline run (Report Section 4.2 — Ingress run ID issuance)."""

    __tablename__ = "run_records"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(255), index=True)
    repository: Mapped[str] = mapped_column(String(512))
    # Value drawn from ci_agent.core.models.common.EventType.
    trigger_type: Mapped[str] = mapped_column(String(32))
    source_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Free string for now; values constrained at the application layer.
    status: Mapped[str] = mapped_column(String(32), default=RUN_STATUS_ACCEPTED)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, onupdate=utcnow)
    # --- Batch 4 additions (runner adapter dispatch tracking) ---------------
    # Convention: "ci-agent/<run_id>" — used by the Execution Observer to map
    # workflow_run/check_run webhooks back to the run (Report Section 4.2).
    dispatch_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # GitHub's workflow run id once resolved after workflow_dispatch.
    external_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # --- Batch 5 addition: explicit pipeline state (Report Section 10) -------
    # Value drawn from ci_agent.orchestrator.run_state.RunState; the control
    # plane's authoritative pipeline position, dual-written with the audit log.
    current_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # sha256 of the registered pipeline spec used for this run (evidence ref).
    pipeline_spec_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RunRecord run_id={self.run_id!r} status={self.status!r}>"


class AuditLogEntry(Base):
    """A single append-only, hash-chained audit event (Report Section 9).

    ``entry_hash = sha256(prev_hash + canonical_json(payload) + event_type +
    created_at.isoformat())``; the first entry of a run uses
    ``prev_hash = "GENESIS"``. ``verify_chain`` (audit_store) recomputes the
    chain to detect tampering.

    Note: ``run_id`` is an indexed plain column, NOT a SQL-level foreign key —
    pre-run rejections (invalid signature, disallowed repository, ...) must be
    auditable before any RunRecord exists, so they are recorded under synthetic
    ids ("rejected:<delivery_id>"). Documented in NOTES.md.
    """

    __tablename__ = "audit_log_entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLogEntry id={self.id} run_id={self.run_id!r} event_type={self.event_type!r}>"


class ProcessedDelivery(Base):
    """A webhook delivery that has already been accepted (replay protection)."""

    __tablename__ = "processed_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ProcessedDelivery delivery_id={self.delivery_id!r}>"


class StageExecutionRecord(Base):
    """Observed execution state of one pipeline stage within a run (Batch 4, Stage 10).

    Section 10: "Represent pipeline state explicitly; do not infer final state
    from free-form logs." One row per (run_id, stage_id) — writes are
    idempotent and transitions are monotonic (ExecutionObserver enforces the
    allowed-transition table; Report Section 7.3 state-confusion control).

    ``logs_ref`` is a pointer/URL, never a full log blob. ``findings_ref`` is
    reserved for Batch 6 (security adapters) — the column exists now so no
    migration redesign is needed later.
    """

    __tablename__ = "stage_execution_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("run_records.run_id"), index=True)
    stage_id: Mapped[str] = mapped_column(String(64), index=True)
    # Value drawn from ci_agent.core.models.common.StageStatus.
    status: Mapped[str] = mapped_column(String(32))
    exit_code: Mapped[int | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(nullable=True)
    logs_ref: Mapped[str | None] = mapped_column(Text(), nullable=True)
    # Reserved for Batch 6 (normalized findings pointer); intentionally nullable now.
    findings_ref: Mapped[str | None] = mapped_column(Text(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<StageExecutionRecord run_id={self.run_id!r} stage_id={self.stage_id!r} "
            f"status={self.status!r}>"
        )


class ApprovalRecord(Base):
    """A human approve/reject decision for an AWAITING_APPROVAL run (Batch 5).

    Part of the compliance evidence package; approver identity is a plain
    string for the MVP (no SSO integration) — see NOTES.md.
    """

    __tablename__ = "approval_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    # "approved" | "rejected" (ApprovalDecision.value)
    decision: Mapped[str] = mapped_column(String(16))
    approver: Mapped[str] = mapped_column(String(255))
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)


class PolicyDecisionRecord(Base):
    """Persisted PDP decision per gated stage (Batch 3 evaluated in-memory).

    Makes every policy/security decision queryable for evidence assembly;
    policy decisions are never retried (Report Section 10) and never inferred
    from runner logs.
    """

    __tablename__ = "policy_decision_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    stage_id: Mapped[str] = mapped_column(String(128))
    # "allow" | "deny" (Decision.outcome) or "unavailable"
    decision: Mapped[str] = mapped_column(String(16))
    policy_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)


class ProjectProfileRecord(Base):
    """Registered project (repository) profile — Batch 5 project registry."""

    __tablename__ = "project_profiles"

    project_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    # "low" | "medium" | "high" (RiskTier.value)
    risk_tier: Mapped[str] = mapped_column(String(16))
    language_stack: Mapped[str] = mapped_column(String(64))
    profile_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, onupdate=utcnow)


class PipelineSpecRecord(Base):
    """Content-addressed pipeline spec versions per project (Batch 5).

    ``content_hash`` is the sha256 of the canonical spec JSON ("spec hash ref"
    in the report); the hash is what run records and evidence reference.
    """

    __tablename__ = "pipeline_specs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(String(255), index=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    spec_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)
