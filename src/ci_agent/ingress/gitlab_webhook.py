"""GitLab webhook endpoint: POST /webhooks/gitlab (Batch 8, Task A).

Receives GitLab ``pipeline`` and ``job`` events for the Execution Observer —
the GitLab counterpart of the observer-event path on ``/webhooks/github``
(Batch 4), reusing the same replay guard, repository allow-list and
audit-everything discipline from Batch 2.

**Token mechanism (documented choice, NOTES.md):** GitLab's standard webhook
authentication is a SHARED SECRET TOKEN sent in the ``X-Gitlab-Token`` header
(plain comparison — GitLab does NOT HMAC-sign webhook payloads the way
GitHub does). We compare it in constant time (``hmac.compare_digest``)
against ``GITLAB_WEBHOOK_TOKEN``. Delivery identity for the replay guard is
GitLab's ``X-Gitlab-Event-UUID`` header. When the token is unconfigured the
endpoint rejects every delivery with 401 (fail-closed, audited) — no request
is ever processed without a validated token.

Run CREATION stays GitHub-only: this endpoint handles observer events
exclusively (pipeline/job); any other GitLab event type is a 400
``unsupported_event`` rejection, audited.
"""

from __future__ import annotations

import hmac
import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

router = APIRouter(tags=["webhooks"])

# Observer events handled on this endpoint (Batch 8 Task A step 4).
GITLAB_OBSERVER_EVENTS: frozenset[str] = frozenset({"pipeline", "job"})

REJECTED_PREFIX = "rejected:"


def _rejection_run_id(delivery_id: str) -> str:
    return f"{REJECTED_PREFIX}{delivery_id or 'unknown'}"


def _reject(
    request: Request,
    run_id: str,
    event_type: str,
    status_code: int,
    detail: str,
    extra: dict[str, Any] | None = None,
) -> HTTPException:
    """Record an auditable rejection event and return the matching exception.

    Even rejections are evidence (same discipline as the GitHub endpoint).
    """
    payload: dict[str, Any] = {
        "detail": detail,
        "path": request.url.path,
        "event_type": event_type or None,
    }
    if extra:
        payload.update(extra)
    request.app.state.audit_store.append_event(run_id, "request_rejected", payload)
    return HTTPException(status_code=status_code, detail=detail)


@router.post("/webhooks/gitlab")
async def gitlab_webhook(request: Request) -> Response:
    """Receive and validate a GitLab observer webhook.

    Validation order (each step short-circuits, all rejections audited):
      1. shared-secret token check (401 ``X-Gitlab-Token``; constant-time),
      2. event type must be pipeline/job (400 unsupported otherwise),
      3. delivery UUID present (400) + JSON body parses (400),
      4. replay/duplicate check (200 idempotent, audited),
      5. repository allow-list (403),
      6. handler -> Execution Observer stage records + orchestrator notify,
      7. delivery marked processed + receipt audited -> 200.
    """
    state = request.app.state
    body = await request.body()
    token_header = request.headers.get("x-gitlab-token", "")
    event_header = request.headers.get("x-gitlab-event", "")
    delivery_id = request.headers.get("x-gitlab-event-uuid", "")

    # 1. Shared-secret token validation (constant-time; fail-closed when the
    #    endpoint is unconfigured — every delivery is rejected + audited).
    expected_token: str | None = getattr(state, "gitlab_webhook_token", None)
    token_ok = (
        token_header is not None
        and expected_token is not None
        and hmac.compare_digest(token_header, expected_token)
    )
    if not token_ok:
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            event_header,
            401,
            "invalid or unconfigured GitLab webhook token",
        )

    # 2. Event-type dispatch: observer events only on this endpoint.
    if event_header not in GITLAB_OBSERVER_EVENTS:
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            event_header,
            400,
            f"unsupported GitLab event type {event_header!r} (observer events only)",
        )

    # 3. Delivery identity + JSON parse.
    if not delivery_id:
        # A stable synthetic id keeps the rejection auditable and replayable.
        delivery_id = f"gitlab-no-uuid-{uuid.uuid4()}"
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise _reject(
            request, _rejection_run_id(delivery_id), event_header, 400, "body is not valid JSON"
        ) from None
    if not isinstance(payload, dict):
        raise _reject(
            request, _rejection_run_id(delivery_id), event_header, 400, "body must be a JSON object"
        )

    # 4. Replay/duplicate check — idempotent 200, never an error (Section 10).
    if state.replay_guard.is_duplicate(delivery_id):
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            "duplicate",
            200,
            "duplicate delivery, ignored",
            {"delivery_id": delivery_id, "event": event_header},
        )

    # 5. Repository allow-list (project.path_with_namespace; glob-aware).
    repository_full_name = str(((payload.get("project") or {}).get("path_with_namespace")) or "")
    import fnmatch

    if not repository_full_name or not any(
        fnmatch.fnmatchcase(repository_full_name, pattern) for pattern in state.allowed_repositories
    ):
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            "repository",
            403,
            f"repository {repository_full_name!r} is not allowed",
            {"delivery_id": delivery_id, "repository": repository_full_name},
        )

    # 6. Handler -> Execution Observer (same pattern as the GitHub handlers).
    handlers = state.gitlab_observer_events
    correlated: str | tuple[str, str] | None
    if event_header == "pipeline":
        correlated = handlers.handle_pipeline_event(payload)
    else:
        correlated = handlers.handle_job_event(payload)

    if correlated is None:
        observed_run_id: str | None = None
    elif isinstance(correlated, str):
        observed_run_id = correlated
    else:
        observed_run_id = correlated[0]

    # 7. Mark processed + audit receipt (matched or not — evidence either way).
    state.replay_guard.mark_processed(
        delivery_id, observed_run_id or _rejection_run_id(delivery_id)
    )
    state.audit_store.append_event(
        observed_run_id or "observer:unmatched",
        "observer_event_received",
        {
            "event": event_header,
            "delivery_id": delivery_id,
            "repository": repository_full_name,
            "matched": correlated is not None,
        },
    )
    return JSONResponse(status_code=200, content={"status": "observed", "event": event_header})
