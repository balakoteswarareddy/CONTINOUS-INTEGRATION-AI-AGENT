"""Project registry (Batch 5, Task A; Report Section 4.2).

Persistence for onboarded projects: a :class:`ProjectProfileRecord` (resolved
by the Batch 2 RequirementsResolver from intake answers) plus content-addressed
:class:`PipelineSpecRecord` versions. The registry is the control plane's
source of truth for "which repositories are allowed to run pipelines at all" —
unregistered projects fail closed at orchestration time.
"""

from ci_agent.db.models import PipelineSpecRecord, ProjectProfileRecord
from ci_agent.projects.admin_api import router as admin_api_router
from ci_agent.projects.project_registry import ProjectRegistry

__all__ = [
    "PipelineSpecRecord",
    "ProjectProfileRecord",
    "ProjectRegistry",
    "admin_api_router",
]
