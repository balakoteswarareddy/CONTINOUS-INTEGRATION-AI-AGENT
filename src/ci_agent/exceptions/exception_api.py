"""Exception admin API (Batch 7, Task D; Sections 6 and 18).

POST /admin/exceptions  — grant a time-boxed exception (the ONLY creation
                          path in the system; same MVP-grade ``X-Admin-Key``
                          control as the Batch 5 admin API — documented
                          hardening item: SSO/RBAC/mTLS pre-production).
GET  /admin/exceptions?project_id=...[&policy_family=...] — list active
                          exceptions (auto-filters expired ones).

These routes live OUTSIDE the policy evaluation path: the PDP may READ
active exceptions to waive a would-be fail, but nothing here is reachable
from the PDP, Planner, or orchestrators (Section 7.3 "Policy bypass";
inspection-tested).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from ci_agent.exceptions.exception_service import ExceptionService
from ci_agent.projects.admin_api import _require_admin_key

router = APIRouter(prefix="/admin/exceptions", tags=["exceptions"])


def _service(request: Request) -> ExceptionService:
    service: ExceptionService = request.app.state.exception_service
    return service


class GrantExceptionRequest(BaseModel):
    """Grant payload — ``expires_at`` is REQUIRED (Section 18)."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(min_length=1)
    policy_family: str = Field(min_length=1)
    # Specific rule to waive; omit for a family-wide exception.
    rule_id: str | None = None
    reason: str = Field(min_length=1)
    granted_by: str = Field(min_length=1)
    expires_at: datetime  # required — no default, no null


class RevokeExceptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revoked_by: str = Field(min_length=1)


def _dump(record: Any) -> dict[str, Any]:
    dumped: dict[str, Any] = record.model_dump(mode="json")
    return dumped


@router.post("", status_code=status.HTTP_201_CREATED)
def grant_exception(
    request: Request,
    response: Response,
    payload: GrantExceptionRequest,
    x_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Grant one time-boxed exception (governed creation path)."""
    _require_admin_key(request, x_admin_key, response)
    try:
        record = _service(request).grant_exception(
            project_id=payload.project_id,
            policy_family=payload.policy_family,
            rule_id=payload.rule_id,
            reason=payload.reason,
            granted_by=payload.granted_by,
            expires_at=payload.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return _dump(record)


@router.get("")
def list_exceptions(
    request: Request,
    response: Response,
    x_admin_key: str | None = Header(default=None),
    project_id: str = Query(min_length=1),
    policy_family: str | None = Query(default=None),
) -> dict[str, Any]:
    """List ACTIVE (non-expired, non-revoked) exceptions for a project."""
    _require_admin_key(request, x_admin_key, response)
    active = _service(request).get_active_exceptions(project_id, policy_family)
    return {
        "project_id": project_id,
        "exceptions": [_dump(record) for record in active],
    }


@router.post("/{exception_id}/revoke")
def revoke_exception(
    exception_id: str,
    request: Request,
    response: Response,
    payload: RevokeExceptionRequest,
    x_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Revoke one exception (it stops waiving immediately)."""
    _require_admin_key(request, x_admin_key, response)
    try:
        record = _service(request).revoke_exception(exception_id, revoked_by=payload.revoked_by)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return _dump(record)


__all__ = ["router"]
