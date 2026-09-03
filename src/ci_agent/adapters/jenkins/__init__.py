"""Jenkins runner adapter (Batch 8, Task B; Report Sections 4.2 and 12).

Polling-only for MVP — no webhook endpoint (see adapter docstring/NOTES.md).
"""

from ci_agent.adapters.jenkins.adapter import (
    JENKINS_RESULT_TO_STAGE_STATUS,
    JenkinsAdapter,
    build_job_config_xml,
    job_name_for_run,
    map_jenkins_result,
)
from ci_agent.adapters.jenkins.compiler import compile_to_jenkinsfile

__all__ = [
    "JENKINS_RESULT_TO_STAGE_STATUS",
    "JenkinsAdapter",
    "build_job_config_xml",
    "compile_to_jenkinsfile",
    "job_name_for_run",
    "map_jenkins_result",
]
