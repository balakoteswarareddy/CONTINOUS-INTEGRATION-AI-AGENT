"""AI-feature API endpoints (Batch 9, Task wiring; Report Section 13 Phase 4).

Three endpoints over the guarded feature layer:

- ``POST /runs/{run_id}/triage/{stage_id}`` — post-hoc failure triage for a
  specific stage of a TERMINAL run. MVP-grade ``X-Admin-Key`` auth (same
  pattern and same caveat as the approval/exception APIs).
- ``POST /runs/{run_id}/summarize`` — executive summary of the management
  report. Same auth.
- ``POST /pipeline-spec/explain`` — design-time explanation of a submitted
  PipelineSpec. NO auth: pipeline structure is "public" classification
  (confirmed by the DataClassifier on the actual payload inside the feature)
  and the endpoint accepts only structure, never credentials or logs.

All three return ADVISORY results. None of them mutates run state, gates,
approvals, or evidence.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from ci_agent.ai.features.failure_triage import FailureTriage, TriageResult
from ci_agent.ai.features.pipeline_explainer import PipelineExplainer
from ci_agent.ai.features.report_summarizer import ReportSummarizer, SummaryResult
from ci_agent.core.models.common import RiskTier
from ci_agent.core.models.pipeline_spec import PipelineSpec
from ci_agent.db.models import FindingRecord, RunRecord
from ci_agent.orchestrator.run_state import TERMINAL_RUN_STATES
from ci_agent.projects.admin_api import _require_admin_key
from ci_agent.projects.project_registry import ProjectNotRegisteredError
from ci_agent.reporting.evidence_assembler import EvidenceAssembler, RunNotFoundError
from ci_agent.reporting.report_models import build_management_report

router = APIRouter(tags=["ai"])

MAX_LOG_SNIPPET_CHARS = 200_000


class TriageRequest(BaseModel):
    """Optional caller-supplied tool-output snippet (never source code)."""

    model_config = ConfigDict(extra="forbid")

    logs_snippet: str = ""


class ExplainRequest(BaseModel):
    """A PipelineSpec document to explain (structure only)."""

    model_config = ConfigDict(extra="forbid")

    spec: dict[str, Any]


class ExplainResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation: str
    stage_summaries: list[str]
    ai_assisted: bool
    fallback_used: bool


def _terminal_run_or_409(request: Request, run_id: str) -> RunRecord:
    assembler: EvidenceAssembler = request.app.state.evidence_assembler
    try:
        run = assembler._require_run(run_id)
    except RunNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if run.current_state not in {state.value for state in TERMINAL_RUN_STATES}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"triage is post-facto: run {run_id!r} is in non-terminal state "
                f"{run.current_state!r}"
            ),
        )
    return run


@router.post(
    "/runs/{run_id}/triage/{stage_id}",
    response_model=TriageResult,
)
def triage_stage(
    run_id: str,
    stage_id: str,
    payload: TriageRequest,
    request: Request,
    response: Response,
    x_admin_key: str | None = Header(default=None),
) -> TriageResult:
    """Advisory failure triage for one stage of a terminal run."""
    _require_admin_key(request, x_admin_key, response)
    _terminal_run_or_409(request, run_id)

    with request.app.state.session_factory() as session:
        findings = list(
            session.execute(
                select(FindingRecord).where(
                    FindingRecord.run_id == run_id, FindingRecord.stage_id == stage_id
                )
            ).scalars()
        )
    logs_snippet = payload.logs_snippet[:MAX_LOG_SNIPPET_CHARS]

    triage: FailureTriage = request.app.state.failure_triage
    result = triage.triage(
        run_id=run_id,
        stage_id=stage_id,
        findings=findings,
        logs_snippet=logs_snippet,
        audit_store=request.app.state.audit_store,
    )
    return result


@router.post(
    "/runs/{run_id}/summarize",
    response_model=SummaryResult,
)
def summarize_run(
    run_id: str,
    request: Request,
    response: Response,
    x_admin_key: str | None = Header(default=None),
) -> SummaryResult:
    """Advisory executive summary of the run's management report."""
    _require_admin_key(request, x_admin_key, response)
    run = _terminal_run_or_409(request, run_id)

    assembler = request.app.state.evidence_assembler
    stages = assembler.stage_records(run_id)
    registry = request.app.state.project_registry
    try:
        profile = registry.get_profile(run.project_id)
        tier: RiskTier | str = profile.risk_tier
    except ProjectNotRegisteredError:
        tier = "unknown"
    report = build_management_report(run, stages, tier)

    summarizer: ReportSummarizer = request.app.state.report_summarizer
    return summarizer.summarize(report, request.app.state.audit_store)


@router.post(
    "/pipeline-spec/explain",
    response_model=ExplainResponse,
)
def explain_pipeline_spec(payload: ExplainRequest, request: Request) -> ExplainResponse:
    """Design-time explanation of a submitted PipelineSpec (no run needed).

    No auth: pipeline structure is "public"-classification content. The
    endpoint accepts STRUCTURE ONLY (stage/tool/template metadata) and the
    feature's guardrails classify + gate whatever is submitted anyway.
    """
    from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy

    try:
        spec = PipelineSpec.model_validate(payload.spec)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid PipelineSpec: {exc}",
        ) from exc

    # Synthesize a design-time ExecutionPlan from the spec's structure:
    # stage order, dependency edges and per-stage tool names. Tool versions
    # are unresolved at design time (no profile) — the explanation uses
    # names, never commands.
    plan = ExecutionPlan(
        run_id=f"explain-{spec.project_id}",
        pipeline_spec_ref="design-time",
        resolved_steps=[
            ResolvedStep(
                step_id=(
                    f"{stage.id}.{stage.required_tools[0]}"
                    if stage.required_tools
                    else f"{stage.id}.{stage.id}"
                ),
                stage_id=stage.id,
                tool_name=stage.required_tools[0] if stage.required_tools else stage.id,
                tool_version="unresolved",
                container_image=None,
                command_template_id="design-time",
                timeout_seconds=300,
                retry_policy=RetryPolicy(),
                depends_on=list(stage.depends_on),
            )
            for stage in spec.stages
        ],
    )
    explainer: PipelineExplainer = request.app.state.pipeline_explainer
    result = explainer.explain(plan, request.app.state.audit_store)
    return ExplainResponse(
        explanation=result.explanation,
        stage_summaries=result.stage_summaries,
        ai_assisted=result.ai_assisted,
        fallback_used=result.fallback_used,
    )
