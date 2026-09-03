"""PolicySpec — the deterministic governance contract.

Report Section 4.1, bullet 2 (the policy specification the Policy Decision
Point evaluates against) plus the seven policy families of the Section 6
table: Identity, Tool, Security, Build, Artifact, Approval, AI.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ci_agent.core.models.common import RiskTier, Severity, validate_semver


class IdentityPolicy(BaseModel):
    """Who and what may run: repo, branch, identity allowlists (Report Section 6 — Identity)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_repositories: list[str] = Field(default_factory=list)
    allowed_branches: list[str] = Field(default_factory=list)
    allowed_identities: list[str] = Field(default_factory=list)


class ToolPolicy(BaseModel):
    """Which tools/images are approved and which are forbidden (Report Section 6 — Tool family)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approved_tool_versions: dict[str, str] = Field(default_factory=dict)
    approved_images: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)


class SecurityPolicy(BaseModel):
    """Scanner severity gates and mandatory scan types (Report Section 6 — Security family)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity_thresholds: dict[Severity, int]
    require_secret_scan: bool
    require_sca: bool


class BuildPolicy(BaseModel):
    """Build sandbox constraints: images, egress, timeouts (Report Section 6 — Build family)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_base_images: list[str] = Field(default_factory=list)
    allowed_egress_domains: list[str] = Field(default_factory=list)
    max_timeout_seconds: int = Field(gt=0)


class ArtifactPolicy(BaseModel):
    """Artifact supply-chain rules: SBOM, signing, registries (Report Section 6 — Artifact)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    require_sbom: bool
    sbom_format: str
    require_signing: bool
    registry_allowlist: list[str] = Field(default_factory=list)


class ApprovalPolicy(BaseModel):
    """When human approval is required and who may grant it (Report Section 6 — Approval family)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    require_human_approval_for: list[RiskTier] = Field(default_factory=list)
    approver_groups: list[str] = Field(default_factory=list)


class AIPolicy(BaseModel):
    """Guardrails for Agent -> LLM provider calls (Report Sections 6 and 7.1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_model_providers: list[str] = Field(default_factory=list)
    allowed_data_classification: list[str] = Field(default_factory=list)
    require_human_override: bool


class PolicySpec(BaseModel):
    """The complete, versioned governance contract (Report Section 4.1, bullet 2 + Section 6).

    This is the deterministic contract the Policy Decision Point (a later
    batch) evaluates against. One instance aggregates all seven policy
    families; individual families are also shipped as standalone versioned
    YAML files under ``ci_agent/governance/catalog/policies/``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str
    identity_policy: IdentityPolicy
    tool_policy: ToolPolicy
    security_policy: SecurityPolicy
    build_policy: BuildPolicy
    artifact_policy: ArtifactPolicy
    approval_policy: ApprovalPolicy
    ai_policy: AIPolicy

    @field_validator("policy_version")
    @classmethod
    def _policy_version_is_semver(cls, value: str) -> str:
        return validate_semver(value)
