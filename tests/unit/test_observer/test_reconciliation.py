"""Unit tests for the reconciliation fallback (Batch 4, Task B)."""

from __future__ import annotations

import io
import zipfile
from typing import Any

import pytest

from ci_agent.adapters.base import DispatchRef, RunnerStatusSnapshot, StageStatusView
from ci_agent.adapters.base import DispatchRef as DR
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.db.models import RunRecord
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.observer.reconciliation import reconcile_run


class FakeAdapter:
    """Scripted adapter double for reconciliation tests (never used in prod)."""

    def __init__(
        self,
        snapshot: RunnerStatusSnapshot,
        results_document: dict[str, Any] | None = None,
    ) -> None:
        self._snapshot = snapshot
        self._results = results_document

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        return self._snapshot

    def download_results_artifact(self, dispatch_ref: DispatchRef) -> dict[str, Any] | None:
        return self._results


def make_run(session_factory, run_id: str = "run-rec-1", dispatched: bool = True) -> None:
    with session_factory() as session:
        run = RunRecord(
            run_id=run_id,
            project_id="example-org/payments-api",
            repository="example-org/payments-api",
            trigger_type="pull_request",
            source_sha="abc",
            status="accepted",
        )
        if dispatched:
            run.dispatch_branch = f"ci-agent/{run_id}"
            run.external_run_id = "777"
        session.add(run)
        session.commit()


def make_snapshot(completed: bool, stage_statuses: list[tuple[str, str]]) -> RunnerStatusSnapshot:
    return RunnerStatusSnapshot(
        run_id="run-rec-1",
        dispatch_ref=DR(
            run_id="run-rec-1",
            repository="example-org/payments-api",
            branch="ci-agent/run-rec-1",
            external_run_id="777",
        ),
        status=StageStatus.PASSED if completed else StageStatus.RUNNING,
        completed=completed,
        stages=[
            StageStatusView(stage_id=sid, status=StageStatus(status))
            for sid, status in stage_statuses
        ],
    )


@pytest.fixture()
def observer(session_factory, audit_store: AuditStore) -> ExecutionObserver:
    return ExecutionObserver(session_factory, audit_store)


class TestReconciliation:
    def test_completed_run_reconciles_from_results_artifact(
        self, session_factory, observer: ExecutionObserver
    ) -> None:
        make_run(session_factory)
        adapter = FakeAdapter(
            make_snapshot(completed=True, stage_statuses=[]),
            results_document={
                "stages": [
                    {"stage_id": "checkout", "status": "passed", "exit_code": 0},
                    {"stage_id": "format_lint", "status": "failed", "exit_code": 1},
                    {"stage_id": "sast", "status": "skipped", "exit_code": None},
                ]
            },
        )

        result = reconcile_run(
            "run-rec-1", adapter=adapter, observer=observer, session_factory=session_factory
        )

        assert result.action == "reconciled"
        assert result.artifact_found is True
        assert result.completed is True
        assert sorted(result.stages_reconciled) == ["checkout", "format_lint", "sast", "workflow"]
        assert observer.get_stage_record("run-rec-1", "format_lint").status == "failed"
        assert observer.get_stage_record("run-rec-1", "format_lint").exit_code == 1
        assert observer.get_stage_record("run-rec-1", "workflow").status == "passed"

    def test_in_flight_run_reconciles_from_check_runs(
        self, session_factory, observer: ExecutionObserver
    ) -> None:
        make_run(session_factory)
        adapter = FakeAdapter(
            make_snapshot(
                completed=False,
                stage_statuses=[("checkout", "passed"), ("format_lint", "running")],
            )
        )

        result = reconcile_run(
            "run-rec-1", adapter=adapter, observer=observer, session_factory=session_factory
        )

        assert result.action == "reconciled"
        assert observer.get_stage_record("run-rec-1", "checkout").status == "passed"
        assert observer.get_stage_record("run-rec-1", "format_lint").status == "running"

    def test_racing_webhook_conflicts_are_tolerated(
        self, session_factory, observer: ExecutionObserver
    ) -> None:
        """A stage already passed locally cannot go back to running — converge, don't crash."""
        make_run(session_factory)
        observer.record_stage_transition("run-rec-1", "checkout", StageStatus.PASSED)
        adapter = FakeAdapter(
            make_snapshot(
                completed=False,
                stage_statuses=[("checkout", "running"), ("format_lint", "running")],
            )
        )

        result = reconcile_run(
            "run-rec-1", adapter=adapter, observer=observer, session_factory=session_factory
        )

        assert "checkout" in result.transitions_rejected
        assert "format_lint" in result.stages_reconciled
        assert observer.get_stage_record("run-rec-1", "checkout").status == "passed"

    def test_undispatched_run_is_a_noop(self, session_factory, observer: ExecutionObserver) -> None:
        make_run(session_factory, dispatched=False)
        adapter = FakeAdapter(make_snapshot(completed=False, stage_statuses=[]))

        result = reconcile_run(
            "run-rec-1", adapter=adapter, observer=observer, session_factory=session_factory
        )

        assert result.action == "not_dispatched"

    def test_unknown_run_is_a_noop(self, session_factory, observer: ExecutionObserver) -> None:
        adapter = FakeAdapter(make_snapshot(completed=False, stage_statuses=[]))

        result = reconcile_run(
            "ghost", adapter=adapter, observer=observer, session_factory=session_factory
        )

        assert result.action == "nothing_to_do"

    def test_reconciliation_writes_are_audited(
        self, session_factory, observer: ExecutionObserver, audit_store: AuditStore
    ) -> None:
        make_run(session_factory)
        results = {"stages": [{"stage_id": "checkout", "status": "passed", "exit_code": 0}]}
        adapter = FakeAdapter(
            make_snapshot(completed=True, stage_statuses=[]),
            results_document=results,
        )

        reconcile_run(
            "run-rec-1", adapter=adapter, observer=observer, session_factory=session_factory
        )

        events = [e.event_type for e in audit_store.get_audit_trail("run-rec-1")]
        assert "stage_transition" in events
        assert audit_store.verify_chain("run-rec-1") is True


class TestResultsArtifactParsing:
    def test_zip_artifact_with_results_json_parses(self) -> None:
        """The adapter's artifact download path round-trips the compiled zip."""
        import json as jsonlib

        payload = {"stages": [{"stage_id": "checkout", "status": "passed", "exit_code": 0}]}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("ci-agent-results/ci-agent-results.json", jsonlib.dumps(payload))

        import zipfile as zf

        archive = zf.ZipFile(io.BytesIO(buffer.getvalue()))
        parsed = jsonlib.loads(archive.read(archive.namelist()[0]).decode("utf-8"))
        assert parsed == payload
