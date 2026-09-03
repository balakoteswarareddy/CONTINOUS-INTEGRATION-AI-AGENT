"""Admin API (Batch 5, Task A): project onboarding + pipeline spec registration.

MVP-grade control: a static ``X-Admin-Key`` header checked against the
``ADMIN_API_KEY`` setting (documented dev default in ``local``). Proper admin
authn/authz (SSO, RBAC, mTLS) is a pre-production hardening item — NOTES.md.
"""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from ci_agent.projects.project_registry import (
    ProjectRegistry,
)

LOGGER = logging.getLogger("ci_agent.projects.admin_api")

router = APIRouter(prefix="/admin", tags=["admin"])


# --------------------------------------------------------------------- models


class RegisterProjectRequest(BaseModel):
    """Onboard a repository: intake answers + the repo it will trigger for."""

    model_config = ConfigDict(extra="forbid")

    repository: str = Field(
        min_length=3,
        description='Full repository name ("org/repo") this profile governs.',
    )
    intake_answers: dict[str, Any]


class RegisterProjectResponse(BaseModel):
    project_id: str
    risk_tier: str
    language_stack: str


class PipelineSpecDocument(BaseModel):
    """Loosely-typed pipeline spec envelope; validated by core models later."""

    model_config = ConfigDict(extra="allow")

    spec: dict[str, Any]


class RegisterPipelineSpecResponse(BaseModel):
    project_id: str
    content_hash: str


# ---------------------------------------------------------------------- guard


def _require_admin_key(request: Request, x_admin_key: str | None, response: Response) -> None:
    """Constant-time ``X-Admin-Key`` check; 401/403 otherwise (MVP-grade)."""
    expected = request.app.state.settings.resolved_admin_api_key()
    if not x_admin_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="missing X-Admin-Key header"
        )
    if not hmac.compare_digest(x_admin_key, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid admin key")
    # No caching of admin responses (keyed operations must never be cached).
    response.headers["Cache-Control"] = "no-store"


def _registry(request: Request) -> ProjectRegistry:
    registry: ProjectRegistry = request.app.state.project_registry
    return registry


# --------------------------------------------------------------------- routes


@router.post(
    "/projects",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterProjectResponse,
)
def register_project(
    payload: RegisterProjectRequest,
    request: Request,
    response: Response,
    x_admin_key: str | None = Header(default=None),
) -> RegisterProjectResponse:
    _require_admin_key(request, x_admin_key, response)
    registry = _registry(request)
    # Batch 9 (Section 13 Phase 4): AI-assisted normalization runs BEFORE the
    # authoritative RequirementsResolver — pre-processing, never a replacement.
    # The model can only suggest values for keys that already exist; missing
    # required fields still fail in the resolver below. Any normalizer failure
    # or fallback leaves the original answers untouched.
    intake_answers: dict[str, Any] = payload.intake_answers
    try:
        normalization = request.app.state.requirement_normalizer.normalize(
            raw_answers=payload.intake_answers,
            intake_schema=request.app.state.intake_schema,
            audit_store=request.app.state.audit_store,
        )
        intake_answers = normalization.normalized
        for warning in normalization.warnings:
            LOGGER.info("intake normalization (%s): %s", payload.repository, warning)
    except Exception:  # normalization must never block onboarding
        LOGGER.exception("AI intake normalization failed; using original answers")
    try:
        record = registry.register_project(
            intake_answers=intake_answers,
            intake_schema=request.app.state.intake_schema,
            repository=payload.repository,
        )
    except Exception as exc:  # resolver raises Missing/Conflicting + ValueError
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return RegisterProjectResponse(
        project_id=record.project_id,
        risk_tier=record.risk_tier,
        language_stack=record.language_stack,
    )


@router.post(
    "/projects/{project_id:path}/pipeline-spec",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterPipelineSpecResponse,
)
def register_pipeline_spec(
    project_id: str,
    payload: PipelineSpecDocument,
    request: Request,
    response: Response,
    x_admin_key: str | None = Header(default=None),
) -> RegisterPipelineSpecResponse:
    _require_admin_key(request, x_admin_key, response)
    registry = _registry(request)
    try:
        record = registry.register_pipeline_spec(project_id, payload.spec)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return RegisterPipelineSpecResponse(project_id=project_id, content_hash=record.content_hash)


@router.get("/projects/{project_id}")
def get_project(
    project_id: str,
    request: Request,
    response: Response,
    x_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_key(request, x_admin_key, response)
    registry = _registry(request)
    try:
        record = registry.get_profile_record(project_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    profile_document: dict[str, Any] = json.loads(record.profile_json)
    return profile_document
