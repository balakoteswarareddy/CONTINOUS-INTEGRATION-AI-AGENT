"""GitHub webhook endpoint: POST /webhooks/github (Batch 2, Task B).

Implements the strict validation order from the batch spec — every step
short-circuits with an appropriate HTTP status, and even rejections are
recorded as audit events (Report Section 4.2 and Section 9: rejections are
auditable evidence). Processing stops at "run accepted, evidence recorded":
no checkout, lint, tests or execution happen in this batch.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from ci_agent.core.models.common import EventType
from ci_agent.ingress.signature import verify_signature

router = APIRouter(tags=["webhooks"])

SUPPORTED_EVENTS: frozenset[str] = frozenset({EventType.PULL_REQUEST.value, EventType.PUSH.value})

# Event name recorded in the audit trail for pre-run rejections. These happen
# before a run exists, so they chain under a synthetic run id derived from the
# delivery id (documented in NOTES.md).
REJECTED_PREFIX = "rejected:"


def _rejection_run_id(delivery_id: str) -> str:
    return f"{REJECTED_PREFIX}{delivery_id or 'unknown'}"


def extract_event_fields(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a GitHub webhook payload into repository/branch/sha fields.

    Supports exactly two event types for now (Batch 2 Task B step 3):
    ``pull_request`` and ``push``. Raises ``ValueError`` for anything else or
    for payloads missing the required fields.
    """
    if event_type not in SUPPORTED_EVENTS:
        raise ValueError(f"unsupported event type: {event_type!r}")

    repository_full_name = str(((payload.get("repository") or {}).get("full_name")) or "")
    if not repository_full_name:
        raise ValueError("payload is missing repository.full_name")

    if event_type == EventType.PULL_REQUEST.value:
        head = (payload.get("pull_request") or {}).get("head") or {}
        branch = str(head.get("ref") or "")
        source_sha = str(head.get("sha") or "")
    else:  # push
        ref = str(payload.get("ref") or "")
        branch = ref.removeprefix("refs/heads/")
        head_commit = payload.get("head_commit") or {}
        source_sha = str(payload.get("after") or head_commit.get("id") or "")

    if not branch:
        raise ValueError(f"could not determine branch for {event_type!r} event")
    if not source_sha:
        raise ValueError(f"could not determine source SHA for {event_type!r} event")

    return {
        "repository": repository_full_name,
        "event_type": event_type,
        "branch": branch,
        "source_sha": source_sha,
    }


def _glob_allows(patterns: list[str], value: str) -> bool:
    """Simple allowlist glob check supporting patterns like ``org/*``."""
    import fnmatch

    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _reject(
    request: Request,
    run_id: str,
    event_type: str,
    status_code: int,
    detail: str,
    extra: dict[str, Any] | None = None,
) -> HTTPException:
    """Record an auditable rejection event and return the matching exception.

    Even rejections are evidence (Batch 2 Task B: "each step must
    short-circuit ... and an AuditLogEntry recorded for the rejection").
    """
    payload: dict[str, Any] = {
        "detail": detail,
        "path": request.url.path,
        "event_type": event_type or None,
    }
    if extra:
        payload.update(extra)
    request.app.state.audit_store.append_event(run_id, _rejection_event_name(event_type), payload)
    return HTTPException(status_code=status_code, detail=detail)


def _rejection_event_name(event_type: str) -> str:
    """Map the rejection to the spec'd audit event names."""
    return {
        "signature": "signature_invalid",
        "unsupported": "unsupported_event",
        "payload": "payload_invalid",
        "repository": "repository_not_allowed",
        "branch": "branch_not_allowed",
        "duplicate": "duplicate_rejected",
    }.get(event_type, "request_rejected")


@router.post("/webhooks/github", status_code=202)
async def github_webhook(request: Request) -> dict[str, str]:
    """Receive and validate a GitHub webhook, then issue a run ID.

    Validation order (each step short-circuits):
      1. raw body bytes (signature verified against raw bytes),
      2. HMAC-SHA256 signature (401, audited ``signature_invalid``),
      3. JSON parse + field extraction (400, audited),
      4. replay/duplicate check (200 idempotent, audited ``duplicate_rejected``),
      5. repository allow-list (403, audited ``repository_not_allowed``),
      6. branch allow-list (403, audited ``branch_not_allowed``),
      7-10. run ID issuance + RunRecord + delivery mark + ``run_created`` audit,
      11. HTTP 202 with the run ID.
    """
    state = request.app.state
    audit_store = state.audit_store
    replay_guard = state.replay_guard
    secret: bytes = state.webhook_secret
    allowed_repositories: list[str] = state.allowed_repositories
    allowed_branches: list[str] = state.allowed_branches

    # 1. Raw body BEFORE any parsing — the signature covers exact bytes.
    body = await request.body()
    signature_header = request.headers.get("x-hub-signature-256", "")
    event_header = request.headers.get("x-github-event", "")
    delivery_id = request.headers.get("x-github-delivery", "")

    # 2. Signature verification (401 on mismatch; never process further).
    if not verify_signature(secret, body, signature_header):
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            "signature",
            401,
            "invalid signature",
        )

    # 3. Parse JSON and extract normalized fields.
    if not delivery_id:
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            "payload",
            400,
            "missing X-GitHub-Delivery header",
        )
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise _reject(
            request, _rejection_run_id(delivery_id), "payload", 400, "body is not valid JSON"
        ) from None
    if not isinstance(payload, dict):
        raise _reject(
            request, _rejection_run_id(delivery_id), "payload", 400, "body must be a JSON object"
        )
    try:
        fields = extract_event_fields(event_header, payload)
    except ValueError as exc:
        code = 400
        kind = "unsupported" if str(exc).startswith("unsupported event type") else "payload"
        raise _reject(request, _rejection_run_id(delivery_id), kind, code, str(exc)) from None

    # 4. Replay/duplicate check — idempotent 200, never an error (Section 10).
    if replay_guard.is_duplicate(delivery_id):
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            "duplicate",
            200,
            "duplicate delivery, ignored",
            {"delivery_id": delivery_id, "repository": fields["repository"]},
        )

    # 5. Repository allow-list (governed identity policy; glob-aware).
    if not _glob_allows(allowed_repositories, fields["repository"]):
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            "repository",
            403,
            f"repository {fields['repository']!r} is not allowed",
            {"delivery_id": delivery_id, "repository": fields["repository"]},
        )

    # 6. Branch allow-list (applies to both supported event types).
    if not _glob_allows(allowed_branches, fields["branch"]):
        raise _reject(
            request,
            _rejection_run_id(delivery_id),
            "branch",
            403,
            f"branch {fields['branch']!r} is not allowed",
            {
                "delivery_id": delivery_id,
                "repository": fields["repository"],
                "branch": fields["branch"],
            },
        )

    # 7. Unique run ID.
    run_id = str(uuid.uuid4())

    # 8. RunRecord (project registry/onboarding arrives later; until then the
    # repository full name doubles as the project identifier — NOTES.md).
    audit_store.create_run(
        run_id=run_id,
        project_id=fields["repository"],
        repository=fields["repository"],
        trigger_type=fields["event_type"],
        source_sha=fields["source_sha"],
    )

    # 9. Mark the delivery processed BEFORE auditing acceptance, so a replay
    # racing this request is still deduped.
    replay_guard.mark_processed(delivery_id, run_id)

    # 10. Audit events: receipt + normalized run creation.
    audit_store.append_event(
        run_id,
        "webhook_received",
        {
            "delivery_id": delivery_id,
            "event_type": fields["event_type"],
            "repository": fields["repository"],
        },
    )
    audit_store.append_event(
        run_id,
        "run_created",
        {
            "repository": fields["repository"],
            "event_type": fields["event_type"],
            "source_sha": fields["source_sha"],
            "branch": fields["branch"],
            "delivery_id": delivery_id,
        },
    )

    # 11. Accepted.
    return {"run_id": run_id, "status": "accepted"}
