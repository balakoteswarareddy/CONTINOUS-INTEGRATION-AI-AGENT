"""ExecutionObserver: monotonic, idempotent stage state tracking (Batch 4, Task B).

Implements Section 10 "State machine: represent pipeline state explicitly" and
the Section 7.3 "State confusion / replay" control: transitions follow an
explicit allowed-transition table (monotonic — a passed stage can never go
back to running), re-recording the same status is an idempotent no-op, and
every write appends a ``stage_transition`` AuditStore event.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.db.models import StageExecutionRecord, utcnow

# Explicit allowed-transition table (monotonic; Section 7.3 / Section 10).
# Re-recording the SAME status is always allowed (idempotency). A first-time
# write may land on any status (reconciliation may observe a terminal state
# without having seen the intermediate ones); transitions are enforced on
# updates only — documented in NOTES.md.
_TERMINAL_ONLY: tuple[StageStatus, ...] = (
    StageStatus.PASSED,
    StageStatus.FAILED,
    StageStatus.SKIPPED,
    StageStatus.CANCELLED,
)

ALLOWED_STAGE_TRANSITIONS: dict[StageStatus, frozenset[StageStatus]] = {
    status: frozenset(
        next_status
        for next_status in StageStatus
        if next_status == status  # same-status re-record is idempotent
    )
    for status in _TERMINAL_ONLY
}
ALLOWED_STAGE_TRANSITIONS.update(
    {
        StageStatus.PENDING: frozenset(
            {
                StageStatus.QUEUED,
                StageStatus.RUNNING,
                StageStatus.PASSED,
                StageStatus.FAILED,
                StageStatus.SKIPPED,
                StageStatus.CANCELLED,
            }
        ),
        StageStatus.QUEUED: frozenset(
            {
                StageStatus.RUNNING,
                StageStatus.PASSED,
                StageStatus.FAILED,
                StageStatus.SKIPPED,
                StageStatus.CANCELLED,
            }
        ),
        StageStatus.RUNNING: frozenset(
            {StageStatus.PASSED, StageStatus.FAILED, StageStatus.SKIPPED, StageStatus.CANCELLED}
        ),
    }
)

TERMINAL_STAGE_STATUSES: frozenset[StageStatus] = frozenset(
    {StageStatus.PASSED, StageStatus.FAILED, StageStatus.SKIPPED, StageStatus.CANCELLED}
)


def _now_if_running(status_value: str) -> datetime | None:
    """started_at is stamped when a stage is first observed running."""
    return utcnow() if status_value == StageStatus.RUNNING.value else None


class InvalidStageTransitionError(Exception):
    """A stage status transition violated the monotonic transition table."""


class ExecutionObserver:
    """Records stage transitions durably and monotonically, with audit.

    Batch 6: ``scan_evidence_collector`` is an optional callable wired in
    create_app (the Security Evidence Service fetcher). When a scan-type
    stage (sast / secret_scan / dependency_scan) is about to reach a terminal
    status, the collector runs BEFORE the row is written terminal — real
    findings must exist before any policy gate that depends on them.
    """

    SCAN_STAGE_IDS: frozenset[str] = frozenset({"sast", "secret_scan", "dependency_scan"})

    def __init__(self, session_factory: sessionmaker[Session], audit_store: AuditStore) -> None:
        self._session_factory = session_factory
        self._audit_store = audit_store
        # Callable(run_id, stage_id) -> None; set by create_app (Batch 6).
        self.scan_evidence_collector: Callable[..., object] | None = None

    def record_stage_transition(
        self,
        run_id: str,
        stage_id: str,
        status: StageStatus | str,
        *,
        exit_code: int | None = None,
        logs_ref: str | None = None,
        occurred_at: datetime | None = None,
    ) -> StageExecutionRecord:
        """Create or update the (run_id, stage_id) record — never duplicate rows.

        - First write creates the row in ``status`` (any status allowed;
          reconciliation may observe terminal states directly).
        - Same-status re-record is an idempotent no-op (row untouched).
        - Any other transition must appear in :data:`ALLOWED_STAGE_TRANSITIONS`,
          else :class:`InvalidStageTransitionError` (monotonic guard).
        - Every call appends a ``stage_transition`` audit event (including
          no-ops, which record ``changed: false`` for traceability).
        """
        status_value = (
            status.value if isinstance(status, StageStatus) else StageStatus(status).value
        )
        current_status, record = self._load(run_id, stage_id)

        # Batch 6: collect scan findings BEFORE the stage lands terminal so
        # the policy gate never runs against missing evidence. A collector
        # error FAILS the transition loudly (fail-closed) rather than marking
        # the stage terminal with unparsed/unparsed-able tool output.
        if (
            status_value in {s.value for s in TERMINAL_STAGE_STATUSES}
            and stage_id in self.SCAN_STAGE_IDS
            and self.scan_evidence_collector is not None
            and (record is None or current_status != status_value)
        ):
            self.scan_evidence_collector(run_id, stage_id)

        changed = False
        if record is None:
            record = StageExecutionRecord(
                run_id=run_id,
                stage_id=stage_id,
                status=status_value,
                exit_code=exit_code,
                started_at=occurred_at or _now_if_running(status_value),
                created_at=utcnow(),
                updated_at=utcnow(),
                logs_ref=logs_ref,
            )
            if status_value == StageStatus.RUNNING.value and record.started_at is None:
                record.started_at = utcnow()
            changed = True
            action = "created"
        else:
            current = StageStatus(current_status)
            new_status = StageStatus(status_value)
            if new_status == current:
                action = "noop"
            elif new_status in ALLOWED_STAGE_TRANSITIONS[current]:
                record.status = status_value
                if exit_code is not None:
                    record.exit_code = exit_code
                if logs_ref is not None:
                    record.logs_ref = logs_ref
                if new_status is StageStatus.RUNNING and record.started_at is None:
                    record.started_at = occurred_at or utcnow()
                if new_status in TERMINAL_STAGE_STATUSES and record.completed_at is None:
                    record.completed_at = occurred_at or utcnow()
                    if record.started_at is not None:
                        record.duration_ms = int(
                            (record.completed_at - record.started_at).total_seconds() * 1000
                        )
                changed = True
                action = "updated"
            else:
                self._audit_store.append_event(
                    run_id,
                    "stage_transition_rejected",
                    {
                        "stage_id": stage_id,
                        "from_status": current.value,
                        "to_status": new_status.value,
                        "reason": "transition violates monotonic stage state machine",
                    },
                )
                raise InvalidStageTransitionError(
                    f"invalid stage transition for run {run_id!r} stage {stage_id!r}: "
                    f"{current.value} -> {new_status.value} "
                    "(transitions must be monotonic)"
                )

        with self._session_factory() as session:
            session.add(record)
            session.commit()
            session.refresh(record)

        self._audit_store.append_event(
            run_id,
            "stage_transition",
            self._event_payload(record, action=action, changed=changed),
        )
        return record

    def get_run_timeline(self, run_id: str) -> list[StageExecutionRecord]:
        """All stage records for ``run_id`` in creation order."""
        with self._session_factory() as session:
            return list(
                session.execute(
                    select(StageExecutionRecord)
                    .where(StageExecutionRecord.run_id == run_id)
                    .order_by(StageExecutionRecord.id)
                ).scalars()
            )

    def get_stage_record(self, run_id: str, stage_id: str) -> StageExecutionRecord | None:
        with self._session_factory() as session:
            return session.execute(
                select(StageExecutionRecord).where(
                    StageExecutionRecord.run_id == run_id,
                    StageExecutionRecord.stage_id == stage_id,
                )
            ).scalar_one_or_none()

    # ------------------------------------------------------------ internals

    def _load(self, run_id: str, stage_id: str) -> tuple[str | None, StageExecutionRecord | None]:
        with self._session_factory() as session:
            record = session.execute(
                select(StageExecutionRecord).where(
                    StageExecutionRecord.run_id == run_id,
                    StageExecutionRecord.stage_id == stage_id,
                )
            ).scalar_one_or_none()
            if record is None:
                return None, None
            return record.status, record

    @staticmethod
    def _event_payload(
        record: StageExecutionRecord, *, action: str, changed: bool
    ) -> dict[str, Any]:
        return {
            "stage_id": record.stage_id,
            "status": record.status,
            "exit_code": record.exit_code,
            "action": action,
            "changed": changed,
            "duration_ms": record.duration_ms,
            "logs_ref": record.logs_ref,
        }
