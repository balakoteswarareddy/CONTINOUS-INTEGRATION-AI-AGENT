"""ProjectProfile — the canonical, validated project profile (Batch 2, Task C).

Report Section 4.2, Requirements Resolver: "Normalize team input into a
canonical project profile; flag missing or conflicting requirements." The
risk tier is DERIVED here via a documented deterministic mapping — it is never
taken from raw input (the intake answer ``derived_risk_tier`` is only used to
raise a warning when human agreement and the computed tier diverge).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ci_agent.core.models.common import RiskTier, validate_semver

# Risk-tier mapping table: (business_criticality, data_sensitivity) -> RiskTier.
#
# Documented, deterministic derivation (Batch 2 Task C Step 3). Rationale:
#   - Data sensitivity dominates: the more sensitive the data the pipeline
#     touches, the more controls apply (Report Section 7.1 data handling).
#   - Business criticality raises the tier when sensitivity alone is
#     ambiguous, because impact of a bad release grows with criticality.
#   - "regulated" is reserved for high/critical criticality combined with
#     confidential/restricted data, where regulatory regimes typically bind
#     (Report Section 14 regulatory_scope intake question).
RISK_TIER_MATRIX: dict[tuple[str, str], RiskTier] = {
    #                     public          internal        confidential    restricted
    ("low", "public"): RiskTier.LOW,
    ("low", "internal"): RiskTier.LOW,
    ("low", "confidential"): RiskTier.MEDIUM,
    ("low", "restricted"): RiskTier.HIGH,
    ("medium", "public"): RiskTier.LOW,
    ("medium", "internal"): RiskTier.MEDIUM,
    ("medium", "confidential"): RiskTier.HIGH,
    ("medium", "restricted"): RiskTier.HIGH,
    ("high", "public"): RiskTier.MEDIUM,
    ("high", "internal"): RiskTier.HIGH,
    ("high", "confidential"): RiskTier.HIGH,
    ("high", "restricted"): RiskTier.REGULATED,
    ("critical", "public"): RiskTier.MEDIUM,
    ("critical", "internal"): RiskTier.HIGH,
    ("critical", "confidential"): RiskTier.REGULATED,
    ("critical", "restricted"): RiskTier.REGULATED,
}


def compute_risk_tier(business_criticality: str, data_sensitivity: str) -> RiskTier:
    """Derive the risk tier from the documented matrix (deterministic).

    Raises ``ValueError`` for combinations outside the intake enums — those are
    rejected earlier by schema validation, so this is a defensive guard.
    """
    key = (business_criticality, data_sensitivity)
    if key not in RISK_TIER_MATRIX:
        raise ValueError(
            f"No risk-tier mapping for business_criticality={business_criticality!r}, "
            f"data_sensitivity={data_sensitivity!r}"
        )
    return RISK_TIER_MATRIX[key]


class ProjectProfile(BaseModel):
    """Canonical project profile produced by the RequirementsResolver (Section 4.2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: str
    business_criticality: str
    data_sensitivity: str
    # DERIVED from business_criticality + data_sensitivity — never taken from input.
    risk_tier: RiskTier
    repo_structure: str
    language_stack: str
    runner: str
    security_tools: list[str] = Field(default_factory=list)
    secret_storage: str
    coverage_requirement: float
    artifact_repository: str
    testing_strategy: str
    execution_location: str
    # PolicySpec version this profile will be evaluated against going forward.
    policy_version_pinned: str
    # Original intake answers, kept verbatim for audit/traceability.
    raw_intake_answers: dict[str, object]
    # Non-fatal flags produced during resolution (Section 4.2: "flag missing
    # or conflicting requirements" — not everything hard-fails).
    resolution_warnings: list[str] = Field(default_factory=list)

    @field_validator("policy_version_pinned")
    @classmethod
    def _policy_version_is_semver(cls, value: str) -> str:
        return validate_semver(value)
