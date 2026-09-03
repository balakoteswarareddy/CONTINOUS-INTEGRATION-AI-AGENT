"""Unit tests for the ExecutionObserver (Batch 4, Task B)."""

from __future__ import annotations

import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.observer.execution_observer import (
    ALLOWED_STAGE_TRANSITIONS,
    ExecutionObserver,
    InvalidStageTransitionError,
)


@pytest.fixture()
def observer(audit_store: AuditStore) -> ExecutionObserver:
    return ExecutionObserver(audit_store._session_factory, audit_store)


class TestValidTransitions:
    def test_running_to_passed(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "checkout", StageStatus.RUNNING)
        record = observer.record_stage_transition(
            "run-1", "checkout", StageStatus.PASSED, exit_code=0
        )

        assert record.status == StageStatus.PASSED.value
        assert record.exit_code == 0

    def test_running_to_failed(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "sast", StageStatus.RUNNING)
        record = observer.record_stage_transition("run-1", "sast", StageStatus.FAILED, exit_code=1)

        assert record.status == StageStatus.FAILED.value
        assert record.exit_code == 1

    def test_first_write_may_be_terminal(self, observer: ExecutionObserver) -> None:
        """Reconciliation may observe terminal states without intermediates."""
        record = observer.record_stage_transition("run-1", "tests", StageStatus.PASSED, exit_code=0)
        assert record.status == StageStatus.PASSED.value

    def test_pending_to_running_sets_started_at(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "lint", StageStatus.RUNNING)
        record = observer.get_stage_record("run-1", "lint")

        assert record is not None
        assert record.started_at is not None

    def test_terminal_write_computes_duration(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "lint", StageStatus.RUNNING)
        record = observer.record_stage_transition("run-1", "lint", StageStatus.PASSED)

        assert record.completed_at is not None
        assert record.duration_ms is not None
        assert record.duration_ms >= 0


class TestInvalidTransitions:
    def test_passed_to_running_rejected(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "checkout", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "checkout", StageStatus.PASSED)

        with pytest.raises(InvalidStageTransitionError, match="passed -> running"):
            observer.record_stage_transition("run-1", "checkout", StageStatus.RUNNING)

    def test_failed_to_passed_rejected(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "sast", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "sast", StageStatus.FAILED)

        with pytest.raises(InvalidStageTransitionError, match="failed -> passed"):
            observer.record_stage_transition("run-1", "sast", StageStatus.PASSED)

    def test_rejection_is_audited(
        self, observer: ExecutionObserver, audit_store: AuditStore
    ) -> None:
        observer.record_stage_transition("run-1", "sast", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "sast", StageStatus.FAILED)

        with pytest.raises(InvalidStageTransitionError):
            observer.record_stage_transition("run-1", "sast", StageStatus.PASSED)

        events = [e.event_type for e in audit_store.get_audit_trail("run-1")]
        assert "stage_transition_rejected" in events

    def test_transition_table_is_monotonic_no_terminal_back_edges(self) -> None:
        for terminal in (
            StageStatus.PASSED,
            StageStatus.FAILED,
            StageStatus.SKIPPED,
            StageStatus.CANCELLED,
        ):
            allowed = ALLOWED_STAGE_TRANSITIONS[terminal]
            assert allowed == {terminal}, f"{terminal} must only re-allow itself, got {allowed}"


class TestIdempotency:
    def test_same_status_rerecord_does_not_duplicate_rows(
        self, observer: ExecutionObserver
    ) -> None:
        observer.record_stage_transition("run-1", "checkout", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "checkout", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "checkout", StageStatus.PASSED)
        observer.record_stage_transition("run-1", "checkout", StageStatus.PASSED)

        timeline = observer.get_run_timeline("run-1")
        assert len(timeline) == 1

    def test_distinct_stages_get_distinct_rows(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "checkout", StageStatus.PASSED)
        observer.record_stage_transition("run-1", "format_lint", StageStatus.PASSED)

        assert len(observer.get_run_timeline("run-1")) == 2

    def test_noop_still_audited_with_changed_false(
        self, observer: ExecutionObserver, audit_store: AuditStore
    ) -> None:
        observer.record_stage_transition("run-1", "checkout", StageStatus.PASSED)
        observer.record_stage_transition("run-1", "checkout", StageStatus.PASSED)

        import json

        events = [
            e for e in audit_store.get_audit_trail("run-1") if e.event_type == "stage_transition"
        ]
        assert len(events) == 2
        second = json.loads(events[1].payload_json)
        assert second["changed"] is False
        assert second["action"] == "noop"


class TestAuditWiring:
    def test_every_write_appends_stage_transition_event(
        self, observer: ExecutionObserver, audit_store: AuditStore
    ) -> None:
        observer.record_stage_transition("run-1", "a", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "a", StageStatus.PASSED)
        observer.record_stage_transition("run-1", "b", StageStatus.SKIPPED)

        events = [e.event_type for e in audit_store.get_audit_trail("run-1")]
        assert events.count("stage_transition") == 3
        # Chain stays verifiable.
        assert audit_store.verify_chain("run-1") is True

    def test_logs_ref_persisted(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition(
            "run-1", "checkout", StageStatus.PASSED, logs_ref="https://logs.example/1"
        )
        record = observer.get_stage_record("run-1", "checkout")

        assert record is not None
        assert record.logs_ref == "https://logs.example/1"


class TestTimeline:
    def test_timeline_is_ordered_and_complete(self, observer: ExecutionObserver) -> None:
        observer.record_stage_transition("run-1", "checkout", StageStatus.PASSED)
        observer.record_stage_transition("run-1", "format_lint", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "format_lint", StageStatus.FAILED)

        timeline = observer.get_run_timeline("run-1")
        assert [r.stage_id for r in timeline] == ["checkout", "format_lint"]
        assert timeline[1].status == StageStatus.FAILED.value

    def test_unknown_run_has_empty_timeline(self, observer: ExecutionObserver) -> None:
        assert observer.get_run_timeline("ghost") == []
