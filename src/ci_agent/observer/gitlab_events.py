"""GitLab webhook event handlers for pipeline / job events (Batch 8, Task A).

Mirrors the GitHub workflow_run / check_run handlers (Batch 4): correlate the
event to a run via the ``ci-agent/<run_id>`` dispatch-branch convention
recorded on the RunRecord at dispatch time, map the runner status vocabulary
through the adapter's explicit table, record the stage transition through the
ExecutionObserver, and notify the orchestrator (entry point 2).

Run correlation (documented in NOTES.md):
- ``pipeline`` events: ``object_attributes.ref`` is the dispatch branch.
- ``job`` events: the ``ref`` field is the dispatch branch; the job NAME is
  the stage id (our compiled GitLab jobs are named exactly ``<stage_id>``,
  same convention as GitHub's job names).
Both lookups match ``dispatch_branch`` OR ``phase_b_branch`` — wave 1 and
wave 2 run on the same branch convention, and Phase B wave-2 dispatches must
correlate too. The ``ci-agent-results`` summary job is skipped (control-plane
job, not a stage).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.adapters.gitlab_ci.adapter import map_gitlab_status
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.db.models import RunRecord
from ci_agent.observer.execution_observer import ExecutionObserver

DISPATCH_BRANCH_PREFIX = "ci-agent/"
WORKFLOW_STAGE_ID = "workflow"  # pseudo-stage for overall pipeline status
RESULTS_JOB_NAME = "ci-agent-results"
UNMATCHED_AUDIT_RUN_ID = "observer:unmatched"


class GitLabEventHandlers:
    """pipeline / job handlers wired into the ingress app (Batch 8)."""

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

    # ------------------------------------------------------------- handlers

    def handle_pipeline_event(self, payload: dict[str, Any]) -> str | None:
        """Record overall pipeline status (the ``workflow`` pseudo-stage).

        Returns the correlated run id, or ``None`` when the event is not ours
        (branch convention mismatch / unknown run) — audited either way.
        """
        attributes = payload.get("object_attributes") or {}
        branch = str(attributes.get("ref") or "")
        if not branch.startswith(DISPATCH_BRANCH_PREFIX):
            self._audit_unmatched("pipeline", f"ref {branch!r} is not a ci-agent dispatch branch")
            return None
        run = self._find_run_by_dispatch_branch(branch)
        if run is None:
            self._audit_unmatched("pipeline", f"no run record with dispatch branch {branch!r}")
            return None
        status = map_gitlab_status(str(attributes.get("status", "")))
        self._observer.record_stage_transition(run.run_id, WORKFLOW_STAGE_ID, status)
        self._notify_orchestrator(run.run_id, WORKFLOW_STAGE_ID, status)
        return run.run_id

    def handle_job_event(self, payload: dict[str, Any]) -> tuple[str, str] | None:
        """Record one stage transition from a job event.

        Returns ``(run_id, stage_id)`` or ``None`` (not ours / summary job).
        """
        job_name = str(payload.get("build_name") or "")
        if not job_name or job_name == RESULTS_JOB_NAME:
            return None  # summary job / unnamed, not a stage
        branch = str(payload.get("ref") or "")
        if not branch.startswith(DISPATCH_BRANCH_PREFIX):
            self._audit_unmatched("job", f"ref {branch!r} is not a ci-agent dispatch branch")
            return None
        run = self._find_run_by_dispatch_branch(branch)
        if run is None:
            self._audit_unmatched("job", f"no run record with dispatch branch {branch!r}")
            return None
        status = map_gitlab_status(str(payload.get("build_status", "")))
        self._observer.record_stage_transition(run.run_id, job_name, status)
        self._notify_orchestrator(run.run_id, job_name, status)
        return run.run_id, job_name

    # ------------------------------------------------------------ internals

    def _find_run_by_dispatch_branch(self, branch: str) -> RunRecord | None:
        """Match the dispatch branch against wave-1 OR wave-2 coordinates."""
        with self._session_factory() as session:
            return session.execute(
                select(RunRecord).where(
                    (RunRecord.dispatch_branch == branch)
                    | (RunRecord.phase_b_branch == branch)
                    | (RunRecord.phase_b_wave2_branch == branch)
                )
            ).scalar_one_or_none()

    def _notify_orchestrator(self, run_id: str, stage_id: str, status: StageStatus) -> None:
        """Orchestrator entry point 2; never breaks event recording."""
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
