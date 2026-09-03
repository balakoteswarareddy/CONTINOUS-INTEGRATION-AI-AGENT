"""Reporting API (Batch 5, Task C): developer / management / compliance views.

GET /runs/{run_id}/report?view=developer|management|compliance and
GET /runs/{run_id} (run summary). Views are assembled on demand from
control-plane tables — never from runner logs.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from ci_agent.core.models.common import RiskTier
from ci_agent.db.models import run_status_from_state
from ci_agent.projects.project_registry import (
    ProjectNotRegisteredError,
    ProjectRegistry,
)
from ci_agent.reporting.evidence_assembler import RunNotFoundError
from ci_agent.reporting.report_models import (
    build_compliance_package,
    build_developer_report,
    build_management_report,
)

router = APIRouter(tags=["reports"])

ViewName = Literal["developer", "management", "compliance", "security"]
_VIEW_QUERY = Query(default="developer")


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


@router.get("/runs/{run_id}")
def get_run(run_id: str, request: Request, response: Response) -> dict[str, Any]:
    """Compact run summary (run record + current state + stage statuses)."""
    _no_store(response)
    assembler = request.app.state.evidence_assembler
    try:
        run = assembler._require_run(run_id)
    except RunNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    stages = assembler.stage_records(run_id)
    return {
        "run_id": run.run_id,
        "project_id": run.project_id,
        "repository": run.repository,
        "trigger_type": run.trigger_type,
        "source_sha": run.source_sha,
        # Batch 5.1 (Item 4): derived from current_state (single source of
        # truth); the legacy RunRecord.status column is deprecated and frozen.
        "status": run_status_from_state(run.current_state),
        "current_state": run.current_state,
        "dispatch_branch": run.dispatch_branch,
        "external_run_id": run.external_run_id,
        "pipeline_spec_ref": run.pipeline_spec_ref,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "stages": [
            {
                "stage_id": s.stage_id,
                "status": s.status,
                "exit_code": s.exit_code,
                "duration_ms": s.duration_ms,
            }
            for s in stages
        ],
    }


@router.get("/runs/{run_id}/report")
def get_report(
    run_id: str,
    request: Request,
    response: Response,
    view: ViewName = _VIEW_QUERY,
) -> dict[str, Any]:
    """Project the run's evidence into the requested report view."""
    _no_store(response)
    state = request.app.state
    assembler = state.evidence_assembler
    try:
        run = assembler._require_run(run_id)
    except RunNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    stages = assembler.stage_records(run_id)
    evidence = assembler.assemble_evidence(run_id)

    if view == "developer":
        developer = build_developer_report(run, stages, findings_count=len(evidence.findings))
        return developer.model_dump(mode="json")

    if view == "security":
        # Batch 6 (Section 9): real scanner name, rule ID, severity,
        # component, location, disposition per finding — no placeholders.
        security = {
            "run_id": run_id,
            "findings": [
                {
                    "scanner": row.scanner,
                    "rule_id": row.rule_id,
                    "severity": row.severity,
                    "component": row.component,
                    "location": row.location,
                    "disposition": row.disposition,
                    "stage_id": row.stage_id,
                }
                for row in assembler.finding_records(run_id)
            ],
            "summary": {
                severity.value: count
                for severity, count in sorted(assembler.findings_summary(run_id).items())
            },
            "parser_warnings": assembler.security_evidence_warnings(run_id),
        }
        return security

    if view == "management":
        registry: ProjectRegistry = state.project_registry
        try:
            profile = registry.get_profile(run.project_id)
            tier: RiskTier | str = profile.risk_tier
        except ProjectNotRegisteredError:
            tier = "unknown"  # runs can exist for unregistered legacy projects
        management = build_management_report(run, stages, tier)
        return management.model_dump(mode="json")

    # compliance
    package = build_compliance_package(
        run,
        evidence,
        policy_decisions=assembler.policy_decisions(run_id),
        approvals=[
            {
                "approver": row.approver,
                "decision": row.decision,
                "comment": row.comment,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in assembler.approval_records(run_id)
        ],
        audit_entries=assembler.audit_entries(run_id),
        stages=stages,
        policy_version=state.pdp.policy_version,
    )
    return package.model_dump(mode="json")


__all__ = ["get_report", "get_run", "router"]
