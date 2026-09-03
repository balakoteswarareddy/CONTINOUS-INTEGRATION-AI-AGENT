"""Polling-based reconciliation fallback (Batch 4, Task B; Report Section 10).

Webhooks can be missed — Section 10's reliability principle demands a polling
fallback that reconciles local stage state against the runner's reported
state. This module is fully implemented now; the scheduler/cron wiring is a
deployment-time concern (NOTES.md).

Usage (MVP CLI):

    python -m ci_agent.observer.reconciliation --run-id <run_id>
"""

from __future__ import annotations

import argparse
import dataclasses
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.adapters.base import DispatchRef
from ci_agent.adapters.github_actions.adapter import GitHubActionsAdapter
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.db.base import get_session_factory
from ci_agent.db.models import RunRecord
from ci_agent.observer.execution_observer import ExecutionObserver, InvalidStageTransitionError


@dataclasses.dataclass
class ReconciliationResult:
    """What a reconciliation pass observed and changed."""

    run_id: str
    workflow_status: StageStatus | None = None
    completed: bool = False
    stages_reconciled: list[str] = dataclasses.field(default_factory=list)
    transitions_rejected: list[str] = dataclasses.field(default_factory=list)
    artifact_found: bool = False
    action: str = "none"  # none | reconciled | nothing_to_do | not_dispatched


def reconcile_run(
    run_id: str,
    *,
    adapter: GitHubActionsAdapter,
    observer: ExecutionObserver,
    session_factory: sessionmaker[Session],
) -> ReconciliationResult:
    """Reconcile one run's stage state against the runner's reported state.

    Preference order (structured evidence first — Section 10):
    1. the ``ci-agent-results`` artifact (per-stage status + exit codes), when
       the workflow has completed;
    2. check-run statuses from ``poll_status`` for in-flight runs;
    3. the overall workflow status, recorded on the ``workflow`` pseudo-stage.
    Monotonic-transition violations from racing webhooks are counted, not
    raised — reconciliation converges instead of crashing.
    """
    with session_factory() as session:
        run = session.execute(
            select(RunRecord).where(RunRecord.run_id == run_id)
        ).scalar_one_or_none()

    if run is None:
        return ReconciliationResult(run_id=run_id, action="nothing_to_do")
    if not run.dispatch_branch or not run.external_run_id:
        return ReconciliationResult(run_id=run_id, action="not_dispatched")

    dispatch_ref = DispatchRef(
        run_id=run_id,
        repository=run.repository,
        branch=run.dispatch_branch,
        external_run_id=run.external_run_id,
    )
    result = ReconciliationResult(run_id=run_id)

    snapshot = adapter.poll_status(dispatch_ref)
    result.workflow_status = snapshot.status
    result.completed = snapshot.completed

    document: dict[str, Any] | None = None
    if snapshot.completed:
        document = adapter.download_results_artifact(dispatch_ref)
        result.artifact_found = document is not None

    if document is not None:
        result.action = "reconciled"
        for row in document.get("stages", []):
            _reconcile_stage(
                result,
                observer,
                run_id,
                str(row.get("stage_id")),
                str(row.get("status", "")),
                row.get("exit_code"),
            )
        # Overall workflow pseudo-stage too (mirrors the webhook path).
        _reconcile_stage(result, observer, run_id, "workflow", snapshot.status.value, None)
        return result

    if snapshot.stages:
        result.action = "reconciled"
        for view in snapshot.stages:
            _reconcile_stage(
                result, observer, run_id, view.stage_id, view.status.value, view.exit_code
            )
        return result

    result.action = "reconciled"
    _reconcile_stage(result, observer, run_id, "workflow", snapshot.status.value, None)
    return result


def _reconcile_stage(
    result: ReconciliationResult,
    observer: ExecutionObserver,
    run_id: str,
    stage_id: str,
    status_value: str,
    exit_code: int | None,
) -> None:
    """Record one reconciled stage transition, tolerating monotonic conflicts."""
    try:
        observer.record_stage_transition(
            run_id, stage_id, StageStatus(status_value), exit_code=exit_code
        )
        result.stages_reconciled.append(stage_id)
    except InvalidStageTransitionError:
        result.transitions_rejected.append(stage_id)


def main() -> int:
    """CLI entry point: python -m ci_agent.observer.reconciliation --run-id <id>."""
    parser = argparse.ArgumentParser(description="Reconcile a ci-agent run against GitHub Actions")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    from ci_agent.adapters.github_actions.client import GitHubAuthConfig, GitHubClient
    from ci_agent.config.settings import get_settings

    settings = get_settings()
    engine = __import__("sqlalchemy").create_engine(settings.database_url)
    factory = get_session_factory(engine)
    audit_store = AuditStore(factory)
    observer = ExecutionObserver(factory, audit_store)
    auth = GitHubAuthConfig(
        pat=settings.github_pat,
        app_id=settings.github_app_id,
        private_key_path=settings.github_app_private_key_path,
        installation_id=settings.github_installation_id,
    )
    adapter = GitHubActionsAdapter(GitHubClient(auth))
    result = reconcile_run(args.run_id, adapter=adapter, observer=observer, session_factory=factory)
    print(
        f"reconcile {result.run_id}: action={result.action} workflow={result.workflow_status} "
        f"stages={result.stages_reconciled} rejected={result.transitions_rejected}"
    )
    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
