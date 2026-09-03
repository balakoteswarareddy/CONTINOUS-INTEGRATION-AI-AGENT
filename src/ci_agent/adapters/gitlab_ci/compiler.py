"""Compile an ExecutionPlan into GitLab CI YAML (Batch 8, Task B; Section 12).

Mirrors the Batch 4 GitHub Actions compiler's invariants exactly:

* **one job per stage** — job KEY ``stage-<stage_id>`` (GitLab's job name ==
  its YAML key), so webhook/observer correlation is identical to GitHub;
* **allow-listed commands only** — every ``script:`` entry is a verbatim
  CommandTemplateRegistry lookup; unknown template ids fail compilation;
* **structured report artifacts** — stages in ``REPORT_UPLOAD_STAGES`` upload
  their raw reports (``artifacts.when: always`` so failing scans still
  upload) with the SAME ``ci-agent-scan-<stage_id>`` names;
* **no secrets** — the generated YAML must never reference credential
  variables; a textual guard hard-fails compilation otherwise;
* **publish target** is the ``CI_AGENT_PUBLISH_REF`` project CI variable
  (a configuration value, not a secret).

Documented deviation (NOTES.md): GitLab's ``needs:`` DAG is used directly
(like GitHub's ``needs:``), so no sequencing compromise exists here.
"""

from __future__ import annotations

from typing import Any

import yaml

from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.github_actions.compiler import (
    CHECKOUT_TEMPLATE_ID,
    GITHUB_JOB_RESULT_TO_STAGE_STATUS,
    REPORT_UPLOAD_STAGES,
    job_id_for_stage,
)
from ci_agent.core.models.execution_plan import ExecutionPlan

PIPELINE_FILE_NAME = "gitlab-ci.yml"
PIPELINE_PATH = ".gitlab-ci.yml"
GATE_TOOL_PREFIX = "internal."

# Publish target: a GitLab CI/CD PROJECT VARIABLE (configuration, not secret).
PUBLISH_ENV_NAME = "CI_AGENT_PUBLISH_REF"

# Credential-shaped references that must never appear in generated YAML.
_FORBIDDEN_FRAGMENTS = (
    "secrets.",
    "withCredentials",
    "$GITLAB_TOKEN",
    "PRIVATE-TOKEN",
    "glpat-",
)

# GitLab job status -> our results-job vocabulary (shared mapping file with
# the GitHub compiler; kept as an explicit re-export for reviewability).
JOB_RESULT_TO_STATUS = GITHUB_JOB_RESULT_TO_STAGE_STATUS


def job_name_for_stage(stage_id: str) -> str:
    """GitLab job key/name for a stage (same convention as GitHub job ids)."""
    return job_id_for_stage(stage_id)


def stage_id_from_job_name(job_name: str) -> str:
    """Inverse of :func:`job_name_for_stage` (webhook correlation)."""
    from ci_agent.adapters.github_actions.compiler import stage_id_from_job_id

    return stage_id_from_job_id(job_name)


def _tool_script(command: str, stage_id: str, tool_name: str) -> list[str]:
    """Allow-listed command with fixed, auditable exit-code capture lines."""
    return [
        f'echo "[{stage_id}] {tool_name}"',
        "set +e",
        command,
        "code=$?",
        'echo "exit_code=$code" >> ci_agent_exit_code.txt',
        "exit $code",
    ]


def compile_to_gitlab_ci(
    plan: ExecutionPlan,
    registry: CommandTemplateRegistry | None = None,
) -> str:
    """Compile ``plan`` into GitLab CI YAML text (round-trip validated)."""
    registry = registry or CommandTemplateRegistry()

    ordered_stage_ids = [step.stage_id for step in plan.resolved_steps]  # topological
    workflow: dict[str, Any] = {
        # Only the control plane triggers pipelines (via the commits + pipeline
        # API on the dedicated ci-agent/<run_id> branch) — never branch pushes.
        "workflow": {
            "rules": [
                {"if": "$CI_PIPELINE_SOURCE == 'parent_pipeline'", "when": "never"},
                {"if": "$CI_PIPELINE_SOURCE == 'pipeline'", "when": "never"},
                {"when": "manual"},
            ]
        },
        "stages": ordered_stage_ids,
        "variables": {PUBLISH_ENV_NAME: "$CI_AGENT_PUBLISH_REF"},
        "default": {"interruptible": True},
    }

    for step in plan.resolved_steps:
        stage_id = step.stage_id
        job: dict[str, Any] = {
            "stage": stage_id,
            "needs": [job_name_for_stage(dep) for dep in step.depends_on],
            "script": [],
        }
        if step.container_image:
            job["image"] = step.container_image
        if step.tool_name.startswith(GATE_TOOL_PREFIX):
            # Control-flow stages are orchestrated by the control plane.
            job["script"] = [
                f'echo "[{stage_id}] {step.tool_name} orchestrated by ci-agent control plane"'
            ]
        elif step.command_template_id == CHECKOUT_TEMPLATE_ID:
            # Native handling: GitLab runners clone the source themselves
            # (default GIT_STRATEGY) — the stage job is the correlation
            # marker, exactly like the GitHub adapter's pinned action.
            job["script"] = [
                f'echo "[{stage_id}] checkout performed natively by the GitLab runner"'
            ]
        else:
            command = registry.get_command(step.command_template_id)
            if command is None:
                # Fail-closed: an unknown template id can never compile.
                raise ValueError(
                    f"no allow-listed command for template {step.command_template_id!r}"
                )
            job["script"] = _tool_script(command, stage_id, step.tool_name)
        if stage_id in REPORT_UPLOAD_STAGES:
            job["artifacts"] = {
                "paths": list(REPORT_UPLOAD_STAGES[stage_id]),
                "when": "always",
                "expire_in": "1 week",
            }
        workflow[job_name_for_stage(stage_id)] = job

    text = str(yaml.safe_dump(workflow, sort_keys=False, default_flow_style=False))
    reparsed = yaml.safe_load(text)
    if not isinstance(reparsed, dict) or "stages" not in reparsed:  # pragma: no cover
        raise ValueError("compiled GitLab CI YAML failed round-trip validation")
    lowered = text
    for fragment in _FORBIDDEN_FRAGMENTS:
        if fragment in lowered:
            raise ValueError(
                f"compiled GitLab CI YAML references credential-shaped fragment "
                f"{fragment!r} — the agent never injects credentials (Section 7.3)"
            )
    return text


__all__ = [
    "PIPELINE_FILE_NAME",
    "PIPELINE_PATH",
    "compile_to_gitlab_ci",
    "job_name_for_stage",
    "stage_id_from_job_name",
]
