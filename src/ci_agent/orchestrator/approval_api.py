"""Human approval API (Batch 5, Task B; Report Section 5.1 human approval).

POST /runs/{run_id}/approve and /runs/{run_id}/reject. Runs are only
actionable in ``AWAITING_APPROVAL`` (otherwise 409). Approver identity is a
plain string for the MVP (no SSO integration — documented deferral); every
decision is persisted as an :class:`ApprovalRecord` and audited, then fed to
the orchestrator which publishes the merge decision.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(tags=["approvals"])


class ApprovalRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approver: str = Field(min_length=1, max_length=255)
    comment: str | None = Field(default=None, max_length=4000)


def _orchestrator(request: Request) -> Any:
    orchestrator = getattr(request.app.state, "orchestrator", None)
    if orchestrator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="orchestrator not wired in this deployment",
        )
    return orchestrator


def _record_approval(
    request: Request,
    run_id: str,
    decision: str,
    body: ApprovalRequestBody,
    response: Response,
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    orchestrator = _orchestrator(request)
    try:
        result = orchestrator.advance(
            run_id,
            {
                "type": "approval",
                "decision": decision,
                "approver": body.approver,
                "comment": body.comment,
            },
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        # Wrong state (not AWAITING_APPROVAL) or invalid decision -> 409.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"run_id": run_id, "decision": decision, **result}


@router.post("/runs/{run_id}/approve")
def approve_run(
    run_id: str,
    body: ApprovalRequestBody,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Approve an AWAITING_APPROVAL run; publishes the merge decision."""
    return _record_approval(request, run_id, "approved", body, response)


@router.post("/runs/{run_id}/reject")
def reject_run(
    run_id: str,
    body: ApprovalRequestBody,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    """Reject an AWAITING_APPROVAL run; publishes the blocked decision."""
    return _record_approval(request, run_id, "rejected", body, response)


__all__ = ["ApprovalRequestBody", "approve_run", "reject_run", "router"]
