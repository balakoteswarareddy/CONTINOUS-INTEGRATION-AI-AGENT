"""Webhook event handlers for workflow_run / check_run (Batch 4, Task B).

Added to the SAME ``/webhooks/github`` endpoint as Batch 2's run-creation flow
(extended event-type dispatch), reusing its signature verification, replay
guard, repository allow-list and audit-everything discipline.

Run correlation (documented in NOTES.md):
- ``workflow_run``: the run is looked up via the dispatch branch convention
  ``ci-agent/<run_id>`` recorded on RunRecord.dispatch_branch at dispatch time.
- ``check_run``: GitHub's payload carries no branch, so the run is resolved by
  matching ``RunRecord.source_sha`` to the check run's head sha (most recent
  dispatch first); the stage comes from the check run name (our compiled jobs
  are named exactly ``<stage_id>``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.adapters.github_actions.adapter import (
    map_check_run,
    map_workflow_run_status,
)
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.db.models import RunRecord
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import MERGE_DECISION_CHECK_NAME

DISPATCH_BRANCH_PREFIX = "ci-agent/"
WORKFLOW_STAGE_ID = "workflow"  # pseudo-stage for overall workflow status
RESULTS_JOB_NAME = "ci-agent-results"
UNMATCHED_AUDIT_RUN_ID = "observer:unmatched"

# Check run names owned by the control plane itself — never mapped to stages.
CONTROL_PLANE_CHECK_NAMES = frozenset({RESULTS_JOB_NAME, MERGE_DECISION_CHECK_NAME})


class ObserverEventHandlers:
    """workflow_run / check_run handlers wired into the ingress app."""

    def __init__(
        self,
        observer: ExecutionObserver,
        audit_store: AuditStore,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._observer = observer
        self._audit_store = audit_store
        self._session_factory = session_factory
        # Optional orchestrator callback (entry point 2), wired in create_app.
        self.on_stage_transition: Callable[..., object] | None = None

    # ------------------------------------------------------------- dispatch

    def handle_workflow_run(self, payload: dict[str, Any]) -> str | None:
        """Record overall run status from a workflow_run event.

        Returns the correlated run id, or ``None`` when the event is not ours
        (branch convention mismatch / unknown run) — audited either way.
        """
        workflow_run = payload.get("workflow_run") or {}
        branch = str(workflow_run.get("head_branch") or "")
        if not branch.startswith(DISPATCH_BRANCH_PREFIX):
            self._audit_unmatched(
                "workflow_run", f"branch {branch!r} is not a ci-agent dispatch branch"
            )
            return None

        run = self._find_run_by_branch(branch)
        if run is None:
            self._audit_unmatched("workflow_run", f"no run record with dispatch_branch {branch!r}")
            return None

        status = map_workflow_run_status(
            str(workflow_run.get("status", "")), workflow_run.get("conclusion")
        )
        self._observer.record_stage_transition(
            run.run_id,
            WORKFLOW_STAGE_ID,
            status,
            logs_ref=self._logs_url(payload),
        )
        self._notify_orchestrator(run.run_id, WORKFLOW_STAGE_ID, status)
        return run.run_id

    def handle_check_run(self, payload: dict[str, Any]) -> tuple[str, str] | None:
        """Record one stage transition from a check_run event.

        Returns ``(run_id, stage_id)`` or ``None`` (not ours / summary job).
        """
        check_run = payload.get("check_run") or {}
        name = str(check_run.get("name") or "")
        if name in CONTROL_PLANE_CHECK_NAMES:
            return None  # results job / published merge decision, not a stage

        head_sha = str(check_run.get("head_sha") or "")
        run = self._find_run_by_sha(head_sha)
        if run is None:
            self._audit_unmatched("check_run", f"no dispatched run with source_sha {head_sha!r}")
            return None

        status = map_check_run(str(check_run.get("status", "")), check_run.get("conclusion"))
        self._observer.record_stage_transition(run.run_id, name, status)
        self._notify_orchestrator(run.run_id, name, status)
        return run.run_id, name

    # ------------------------------------------------------------ internals

    def _find_run_by_branch(self, branch: str) -> RunRecord | None:
        with self._session_factory() as session:
            return session.execute(
                select(RunRecord).where(RunRecord.dispatch_branch == branch)
            ).scalar_one_or_none()

    def _find_run_by_sha(self, head_sha: str) -> RunRecord | None:
        if not head_sha:
            return None
        with self._session_factory() as session:
            return session.execute(
                select(RunRecord)
                .where(
                    RunRecord.source_sha == head_sha,
                    RunRecord.dispatch_branch.is_not(None),
                )
                .order_by(RunRecord.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()

    def _notify_orchestrator(self, run_id: str, stage_id: str, status: StageStatus) -> None:
        """Orchestrator entry point 2 (Batch 5); never breaks event recording."""
        callback = self.on_stage_transition
        if callback is None:
            return
        try:
            callback(run_id, stage_id, status.value)
        except Exception:
            self._audit_unmatched(
                "orchestrator_notify",
                f"stage {stage_id!r} notification failed for run {run_id!r}",
            )

    def _audit_unmatched(self, event: str, reason: str) -> None:
        """Unmatched events are still evidence — audited under a synthetic id."""
        self._audit_store.append_event(
            UNMATCHED_AUDIT_RUN_ID,
            "observer_event_unmatched",
            {"event": event, "reason": reason},
        )

    @staticmethod
    def _logs_url(payload: dict[str, Any]) -> str | None:
        workflow_run = payload.get("workflow_run") or {}
        logs_url = workflow_run.get("logs_url")
        return str(logs_url) if logs_url else None


def overall_status_completed(status: StageStatus) -> bool:
    """True when the mapped workflow status is terminal."""
    return status in {
        StageStatus.PASSED,
        StageStatus.FAILED,
        StageStatus.CANCELLED,
        StageStatus.SKIPPED,
    }
