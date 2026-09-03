"""GitLab webhook ingestion (Batch 8, Task B).

POST /webhooks/gitlab — GitLab **Job Hook** events mapped onto the same
stage-transition seam the GitHub events use:

* secret check via the ``X-GITLAB-TOKEN`` header (constant-time compare);
* replay guard on the job id (same ``ProcessedDelivery`` discipline);
* run resolution: the pipeline id in the payload must match a RunRecord with
  ``runner_provider == 'gitlab_ci'`` and ``external_run_id == pipeline_id`` —
  runs of OTHER providers are never touched (isolation, tested);
* stage correlation: job name ``stage-<stage_id>`` (the compiler's convention);
* status mapping: explicit, fail-closed table (unknown → FAILED, never
  silently ignored).

Control-plane orchestrated stages (policy gates) are filtered the same way
Phase A's ``on_stage_transition`` filters internal.* events.
"""

from __future__ import annotations

import hmac
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from ci_agent.adapters.gitlab_ci.adapter import map_gitlab_status
from ci_agent.adapters.gitlab_ci.compiler import stage_id_from_job_name
from ci_agent.core.models.common import StageStatus
from ci_agent.db.models import RunRecord

router = APIRouter(tags=["webhooks"])

LOGGER = logging.getLogger("ci_agent.ingress.gitlab")

RUNNER_PROVIDER = "gitlab_ci"


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _resolve_run(session_factory: Any, pipeline_id: str) -> RunRecord | None:
    """The GitLab run whose external id matches the payload's pipeline id."""
    with session_factory() as session:
        record: RunRecord | None = (
            session.execute(
                select(RunRecord).where(
                    RunRecord.runner_provider == RUNNER_PROVIDER,
                    RunRecord.external_run_id == str(pipeline_id),
                )
            )
            .scalars()
            .first()
        )
        if record is not None:
            session.expunge(record)
        return record


@router.post("/webhooks/gitlab")
async def gitlab_webhook(request: Request, response: Response) -> dict[str, Any]:
    """Ingest one GitLab Job Hook event (Section 10: structured evidence only)."""
    settings = request.app.state.settings
    expected_token = getattr(settings, "gitlab_webhook_token", None) or ""
    provided_token = request.headers.get("X-GITLAB-TOKEN", "")
    if not expected_token or not _constant_time_equal(provided_token, expected_token):
        # Fail closed with 401 (same discipline as the GitHub webhook);
        # never process an unauthenticated payload further.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-GITLAB-TOKEN",
        )

    payload = await request.json()
    event_name = request.headers.get("X-Gitlab-Event", "")
    if event_name != "Job Hook":
        return {"status": "ignored", "reason": f"event {event_name!r} not handled"}

    # Replay guard keyed on the job id (dedupe across GitLab retries).
    job_id = str(payload.get("job_id", ""))
    delivery_id = f"gitlab-job-{job_id}" if job_id else ""
    replay_guard = request.app.state.replay_guard
    if delivery_id:
        if replay_guard.is_duplicate(delivery_id):
            return {"status": "duplicate", "delivery_id": delivery_id}
        replay_guard.mark_processed(delivery_id, "")

    build_status = str(payload.get("build_status", ""))
    build_name = str(payload.get("build_name", ""))
    pipeline_id = str(payload.get("pipeline_id", ""))
    if not build_name.startswith("stage-"):
        return {"status": "ignored", "reason": f"job {build_name!r} is not a ci-agent stage job"}

    session_factory = request.app.state.session_factory
    run = _resolve_run(session_factory, pipeline_id)
    if run is None:
        # Not ours / not a gitlab_ci run: isolation — never touch other runs.
        return {"status": "ignored", "reason": "no run for this pipeline id"}

    stage_status = map_gitlab_status(build_status)
    if stage_status not in (StageStatus.PASSED, StageStatus.FAILED, StageStatus.CANCELLED):
        # In-progress/queued job states are already reconciled from the
        # structured pipeline API; webhook only lands terminal transitions.
        return {"status": "ignored", "reason": f"non-terminal status {build_status!r}"}

    observer_events = request.app.state.observer_events
    stage_id = stage_id_from_job_name(build_name)
    outcome = observer_events.on_stage_transition(run.run_id, stage_id, stage_status.value)
    response.status_code = status.HTTP_202_ACCEPTED
    return {
        "status": "accepted",
        "run_id": run.run_id,
        "stage_id": stage_id,
        "stage_status": stage_status.value,
        "outcome": outcome,
    }


__all__ = ["router"]
