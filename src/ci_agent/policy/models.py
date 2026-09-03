"""Data contracts for the Policy Decision Point (Batch 3, Task A).

``PolicyInputFacts`` bundles everything OPA needs to decide;
``PolicyDecisionResult`` is the deterministic outcome (Report Section 4.2:
"Use policy-as-code rather than model-generated decisions").
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ci_agent.core.models.common import PolicyDecision


class PolicyInputFacts(BaseModel):
    """Facts submitted to OPA for one gate evaluation (Batch 3 Task A).

    ``run_id`` is optional bookkeeping used by the PolicyDecisionPoint to
    persist the evaluation as an audit event (Batch 2 AuditStore); it is not
    part of the policy facts proper.
    """

    model_config = ConfigDict(extra="forbid")

    project_profile: dict[str, Any]
    pipeline_spec: dict[str, Any]
    proposed_execution_plan: dict[str, Any] | None = None
    stage_id: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    # Approval records ({approver_group, status}) known at evaluation time —
    # required to evaluate approval gates positively once a human approves.
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    # {model_provider, data_classification, human_override} when an AI model
    # invocation is under evaluation; None means no AI model is involved.
    ai_invocation: dict[str, Any] | None = None
    run_id: str | None = None


class PolicyDecisionResult(BaseModel):
    """Aggregated, deterministic decision for one gate (always fail-closed)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: PolicyDecision
    reasons: list[str] = Field(default_factory=list)
    policy_family: str
    policy_version: str
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
