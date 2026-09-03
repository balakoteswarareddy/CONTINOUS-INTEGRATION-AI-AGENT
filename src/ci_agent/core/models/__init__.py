"""Canonical data models (CI-Agent Production Architecture Report, Section 4.1).

The four models defined here — PipelineSpec, PolicySpec, ExecutionPlan and
EvidenceModel — are the data contracts every other component depends on
(Planner, Policy Engine, Runner Adapters, Evidence Store, Report Generator).
They are the internal source of truth; YAML is only a human-authored
interface that is compiled into these structures.
"""

from ci_agent.core.models.common import (
    ApprovalStatus,
    EventType,
    PolicyDecision,
    RiskTier,
    Severity,
    StageStatus,
    validate_semver,
)
from ci_agent.core.models.evidence_model import ApprovalRecord, ArtifactRef, EvidenceModel, Finding
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy
from ci_agent.core.models.pipeline_spec import (
    PipelineSpec,
    RepositoryRef,
    StackInfo,
    StageDefinition,
    TriggerInfo,
)
from ci_agent.core.models.policy_spec import (
    AIPolicy,
    ApprovalPolicy,
    ArtifactPolicy,
    BuildPolicy,
    IdentityPolicy,
    PolicySpec,
    SecurityPolicy,
    ToolPolicy,
)

__all__ = [
    "AIPolicy",
    "ApprovalPolicy",
    "ApprovalRecord",
    "ApprovalStatus",
    "ArtifactPolicy",
    "ArtifactRef",
    "BuildPolicy",
    "EventType",
    "EvidenceModel",
    "ExecutionPlan",
    "Finding",
    "IdentityPolicy",
    "PipelineSpec",
    "PolicyDecision",
    "PolicySpec",
    "RepositoryRef",
    "ResolvedStep",
    "RetryPolicy",
    "RiskTier",
    "SecurityPolicy",
    "Severity",
    "StackInfo",
    "StageDefinition",
    "StageStatus",
    "ToolPolicy",
    "TriggerInfo",
    "validate_semver",
]
