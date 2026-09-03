"""GitLab CI runner adapter (Batch 8, Task A; Report Sections 4.2 and 12)."""

from ci_agent.adapters.gitlab_ci.adapter import (
    GITLAB_STATUS_TO_STAGE_STATUS,
    GitLabCIAdapter,
    map_gitlab_status,
)
from ci_agent.adapters.gitlab_ci.compiler import compile_to_gitlab_ci

__all__ = [
    "GITLAB_STATUS_TO_STAGE_STATUS",
    "GitLabCIAdapter",
    "compile_to_gitlab_ci",
    "map_gitlab_status",
]
