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

# Legacy single-value vocabulary for RunRecord.status (Batch 2).
# DEPRECATED (Batch 5.1, Item 4): `RunRecord.current_state` (RunState enum) is
# the single source of truth for pipeline position. `status` exists ONLY for
# backward compatibility with pre-Batch-5 rows/tests; it is written once by
# the ORM insert default below and NEVER updated by any code path. All
# external-facing display derives from current_state via
# run_status_from_state(). Do not read or write `status` in new code.
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
    # DEPRECATED (Batch 5.1, Item 4 — see RUN_STATUS_ACCEPTED note above):
    # legacy insert-only column, frozen at "accepted"; the authoritative
    # pipeline position is `current_state` (RunState). Never updated.
    status: Mapped[str] = mapped_column(String(32), default=RUN_STATUS_ACCEPTED)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, onupdate=utcnow)
    # --- Batch 4 additions (runner adapter dispatch tracking) ---------------
    # Convention: "ci-agent/<run_id>" — used by the Execution Observer to map
    # workflow_run/check_run webhooks back to the run (Report Section 4.2).
    dispatch_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # GitHub's workflow run id once resolved after workflow_dispatch.
    external_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # --- Batch 7 additions (Phase B supply-chain waves) ----------------------
    # The SECOND workflow run (Phase B) dispatched to the same branch after an
    # approved Phase A merge decision; evidence downloads use these coords.
    phase_b_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phase_b_external_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # --- Batch 8 additions (Batch 7.1 folded-in Fix B: wave-2 coordinates) ---
    # The publish wave (wave 2) is dispatched ONLY after the publish gate
    # passes; its dispatch coordinates are persisted HERE — on the RunRecord,
    # retrievable from the DB directly, not only from audit event payloads.
    # Same table/naming convention as the wave-1 equivalents above.
    phase_b_wave2_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phase_b_wave2_external_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # --- Batch 5 addition: explicit pipeline state (Report Section 10) -------
    # Value drawn from ci_agent.orchestrator.run_state.RunState; the control
    # plane's authoritative pipeline position, dual-written with the audit log.
    current_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # sha256 of the registered pipeline spec used for this run (evidence ref).
    pipeline_spec_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RunRecord run_id={self.run_id!r} current_state={self.current_state!r}>"


# Batch 5.1 (Item 4): the ONLY sanctioned status vocabulary for external
# display, derived from current_state. None (run created, orchestration has
# not advanced it yet) maps to the legacy "accepted". An unrecognized state
# value maps fail-closed to "error" rather than pretending progress.
_RUN_STATE_TO_STATUS: dict[str, str] = {
    "trigger_validated": "in_progress",
    "checked_out": "in_progress",
    "baseline_validated": "in_progress",
    "linted": "in_progress",
    "sast_done": "in_progress",
    "tests_done": "in_progress",
    "security_checked": "in_progress",
    "policy_gate_eval": "in_progress",
    "awaiting_approval": "awaiting_approval",
    "approved": "approved",
    "rejected": "rejected",
    "merge_decision_published": "published",
    "failed": "failed",
    "error": "error",
    # --- Phase B (Batch 7, Section 5.2) -------------------------------------
    "built": "in_progress",
    "integration_tested": "in_progress",
    "coverage_checked": "in_progress",
    "container_built": "in_progress",
    "sbom_generated": "in_progress",
    "image_scanned": "in_progress",
    "signed": "in_progress",
    "published": "in_progress",
    "evidence_recorded": "succeeded",
}


def run_status_from_state(current_state: str | None) -> str:
    """Derive the external-facing run status from the authoritative state.

    Single mapping used by every display/API surface so `status` and
    `current_state` cannot disagree by construction (Batch 5.1 Item 4).
    """
    if current_state is None:
        return RUN_STATUS_ACCEPTED
    return _RUN_STATE_TO_STATUS.get(current_state, "error")


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

    ``logs_ref`` is a pointer/URL, never a full log blob. ``findings_ref``
    (Batch 6): a small summary JSON blob ``{"count": N, "by_severity":
    {...}, "parser_warnings": [...]}`` written by the Security Evidence
    Service. ``FindingRecord`` rows are the source of truth for finding
    DETAIL; this is a cheap per-stage rollup so reports need no join to say
    "how many HIGHs did this stage produce". Documented decision: summary
    here, detail in FindingRecord — no duplication of full rows.
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
    # Batch 6: per-stage findings summary JSON (see class docstring).
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
    # Batch 7: JSON array of exception ids that waived this decision
    # (Section 9 — exception/waiver ID must be visible in policy evidence).
    exception_ids_json: Mapped[str | None] = mapped_column(Text(), nullable=True)
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


class FindingRecord(Base):
    """One normalized security finding for a run (Batch 6; Report Section 9).

    The source of truth for finding detail (severity, scanner, rule id,
    component, location, disposition). Rows are written ONLY by the Security
    Evidence Service, which guarantees that secret VALUES (e.g. gitleaks'
    ``Secret``/``Match`` fields) never reach this table — location and rule
    identity only (tested explicitly).
    """

    __tablename__ = "finding_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("run_records.run_id"), index=True)
    stage_id: Mapped[str] = mapped_column(String(64), index=True)
    scanner: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(128))
    # Governed Severity vocabulary (critical/high/medium/low/info).
    severity: Mapped[str] = mapped_column(String(16))
    component: Mapped[str | None] = mapped_column(Text(), nullable=True)
    description: Mapped[str] = mapped_column(Text(), default="")
    location: Mapped[str | None] = mapped_column(Text(), nullable=True)
    # "open" until a governed waiver/disposition flow (later batch) changes it.
    disposition: Mapped[str] = mapped_column(String(16), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<FindingRecord run_id={self.run_id!r} scanner={self.scanner!r} "
            f"rule_id={self.rule_id!r} severity={self.severity!r}>"
        )


class ArtifactRecord(Base):
    """One built artifact of a run, identified by its immutable digest.

    Batch 7 (Report Section 8 — "Use immutable digest as the primary
    identity; do not treat tags alone as integrity evidence"). Rows are
    written ONLY by :class:`ci_agent.supplychain.sbom_service.SBOMService`
    from build output that carries a registry/computed digest — a mutable
    tag is never accepted as identity (tested).

    ``sbom_ref``/``signature_ref`` are pointers into the evidence store (not
    blobs); they fill in as the SBOM/signing stages complete.
    """

    __tablename__ = "artifact_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("run_records.run_id"), index=True)
    # sha256:<64 hex> — unique across the registry (immutable identity).
    digest: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    # Registry HOST ("ghcr.io") — attribute renamed (registry_host) because
    # `registry` collides with SQLAlchemy's DeclarativeBase.registry.
    registry_host: Mapped[str] = mapped_column("registry", String(512))
    sbom_ref: Mapped[str | None] = mapped_column(Text(), nullable=True)
    signature_ref: Mapped[str | None] = mapped_column(Text(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ArtifactRecord run_id={self.run_id!r} digest={self.digest!r}>"


class ExceptionRecord(Base):
    """A governed security exception/waiver (Batch 7; Sections 6 and 18).

    Rows are written ONLY by
    :meth:`ci_agent.exceptions.exception_service.ExceptionService.grant_exception`
    — the PDP, Planner and orchestrators have NO code path that can create or
    auto-apply an exception (Section 7.3 "Policy bypass" threat; inspection-
    tested). ``expires_at`` is NOT NULL: a permanent exception can never be
    created (Section 18 — non-negotiable).
    """

    __tablename__ = "exception_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(255), index=True)
    # Policy family this exception covers (e.g. security_policy) + the rule
    # it waives. rule_id "*" (or NULL) = every rule of the family.
    policy_family: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason: Mapped[str] = mapped_column(Text())
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)
    # REQUIRED (Section 18: "exceptions ... have expiration times"). No
    # default: a grant without an explicit expiry is rejected by the service
    # and the column is non-nullable at the DB level.
    expires_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    # active / revoked / expired (expired is a derived state enforced by
    # comparison against the clock at read time; the cleanup job only flips
    # the stored status for hygiene).
    status: Mapped[str] = mapped_column(String(16), default="active")
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ExceptionRecord id={self.id!r} project_id={self.project_id!r} "
            f"policy_family={self.policy_family!r} expires_at={self.expires_at!r}>"
        )


class SignatureRecordRow(Base):
    """A recorded signature reference (Batch 7; Section 8 signature row).

    Written ONLY by the SigningService. Key material NEVER reaches this
    table — references and an integrity hash of the signature file only
    (tested). ``artifact_digest`` is the immutable identity; the mutable
    publish tag is not recorded here at all.
    """

    __tablename__ = "signature_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("run_records.run_id"), index=True)
    artifact_digest: Mapped[str] = mapped_column(String(128), index=True)
    signature_ref: Mapped[str] = mapped_column(Text())
    bundle_ref: Mapped[str | None] = mapped_column(Text(), nullable=True)
    # True = keyless OIDC signing (Section 7.2 preference).
    keyless: Mapped[bool] = mapped_column(default=False)
    signature_sha256: Mapped[str] = mapped_column(String(64))
    signed_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SignatureRecordRow digest={self.artifact_digest!r} ref={self.signature_ref!r}>"


class ProvenanceRecordRow(Base):
    """A recorded in-toto/SLSA provenance attestation (Batch 7; Section 8).

    The subject digest was verified to EQUAL the artifact digest at record
    time (tamper detection, tested). The attestation itself lives in the
    evidence store; this row keeps the pointer + content hash.
    """

    __tablename__ = "provenance_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("run_records.run_id"), index=True)
    artifact_digest: Mapped[str] = mapped_column(String(128), index=True)
    attestation_ref: Mapped[str] = mapped_column(Text())
    predicate_type: Mapped[str] = mapped_column(String(255))
    attestation_sha256: Mapped[str] = mapped_column(String(64))
    subject_digest: Mapped[str] = mapped_column(String(128))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ProvenanceRecordRow digest={self.artifact_digest!r} "
            f"predicate={self.predicate_type!r}>"
        )


class AIInvocationRecord(Base):
    """One model-gateway invocation (Batch 9; Report Sections 6 and 7.3).

    EVERY invocation is logged here regardless of outcome (success, provider
    failure, policy rejection, no-model fallback). The row carries HASHES,
    never content: the prompt may contain source code which is potentially
    confidential, so only ``prompt_hash``/``response_hash`` (sha256,
    ``sha256:...`` format) are stored. ``run_id`` is nullable — some
    invocations (intake normalization, design-time explanation) are not
    run-scoped.
    """

    __tablename__ = "ai_invocation_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("run_records.run_id"), nullable=True, index=True
    )
    feature: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(64))
    context_classification: Mapped[str] = mapped_column(String(32))
    prompt_hash: Mapped[str] = mapped_column(String(80))
    response_hash: Mapped[str] = mapped_column(String(80))
    tokens_used: Mapped[int | None] = mapped_column(nullable=True)
    latency_ms: Mapped[int] = mapped_column(default=0)
    fallback_used: Mapped[bool] = mapped_column(default=False)
    policy_allowed: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<AIInvocationRecord feature={self.feature!r} provider={self.provider!r} "
            f"policy_allowed={self.policy_allowed!r}>"
        )
