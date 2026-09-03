"""Requirements Resolver (Batch 2, Stage 6)."""

from ci_agent.resolver.project_profile import RISK_TIER_MATRIX, ProjectProfile, compute_risk_tier
from ci_agent.resolver.requirements_resolver import (
    ConflictingRequirementsError,
    MissingRequirementsError,
    RequirementsResolver,
)

__all__ = [
    "RISK_TIER_MATRIX",
    "ConflictingRequirementsError",
    "MissingRequirementsError",
    "ProjectProfile",
    "RequirementsResolver",
    "compute_risk_tier",
]
