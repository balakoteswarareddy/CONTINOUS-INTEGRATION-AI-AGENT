"""Compile an ExecutionPlan into a ``.gitlab-ci.yml`` (Batch 8, Task A).

Mirrors the GitHub Actions compiler's documented decisions (NOTES.md):

- **One job per stage**: GitLab ``stages:`` lists every stage in the plan's
  topological (Planner) order and each job declares ``stage: <stage_id>``,
  so stage-level sequencing preserves the dependency order exactly. Gate
  stages (``internal.*`` tool names) compile to jobs that immediately
  ``exit 0`` — they are orchestrated by the control plane.
- **Allow-listed commands only**: every ``script:`` entry is a verbatim
  lookup from the SHARED command template registry (Batch 4 — the registry
  is runner-agnostic by design; there is deliberately NO GitLab-specific
  command registry). Unknown ids fail compilation immediately.
- **Explicit trigger control**: the compiled pipeline runs only when
  triggered via the API (``workflow: rules: $CI_PIPELINE_SOURCE == "api"``)
  — the GitLab analogue of the GitHub adapter's ``workflow_dispatch``-only
  decision. Pushing the file to the ``ci-agent/<run_id>`` branch does NOT
  start a second, uncontrolled pipeline.
- **Structured results artifact**: every stage job writes a
  ``<stage_id>.result.json`` (status + exit code, from the job's own
  captured exit code — never parsed logs) in ``after_script`` and uploads it
  with ``artifacts: when: always`` so a FAILING stage still produces its
  result. The final always-run ``ci-agent-results`` job merges those files
  into ``ci-agent-results.json`` and uploads it — the same observation
  contract the GitHub adapter implements, not a GitLab-specific feature.
- The generated YAML is round-trip validated (``yaml.safe_load``) and the
  ``secrets.`` context reference is a hard compile failure, identical to the
  GitHub compiler's credential-leak guard.
"""

from __future__ import annotations

from typing import Any

import yaml

from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.github_actions.compiler import (
    CHECKOUT_TEMPLATE_ID,
    GATE_TOOL_PREFIX,
    REPORT_UPLOAD_STAGES,
)
from ci_agent.core.models.execution_plan import ExecutionPlan

PIPELINE_FILE_NAME = ".gitlab-ci.yml"
RESULTS_JOB_NAME = "ci-agent-results"
RESULTS_ARTIFACT_FILE = "ci-agent-results.json"
RESULT_FILE_SUFFIX = ".result.json"
EXIT_CODE_FILE = "ci-agent-exit-code"

# Only API-triggered pipelines run (explicit control — see module docstring).
WORKFLOW_RULE = '$CI_PIPELINE_SOURCE == "api"'

# Fail-closed result derivation from the captured exit code (POSIX sh).
_AFTER_SCRIPT_TEMPLATE = (
    "code=$(cat {exit_code_file} 2>/dev/null || echo 1) && "
    'if [ "$code" = "0" ]; then st=passed; else st=failed; fi && '
    'printf \'{{"stage_id": "{stage_id}", "status": "%s", "exit_code": %s}}\\n\' '
    '"$st" "$code" > "{result_file}"'
)

# The final job merges the per-stage result files (python3 on ubuntu runners,
# same assumption the GitHub summary job makes).
_RESULTS_PY_SCRIPT = (
    "import glob, json\n"
    "rows = []\n"
    "for path in sorted(glob.glob('*" + RESULT_FILE_SUFFIX + "')):\n"
    "    with open(path, encoding='utf-8') as handle:\n"
    "        rows.append(json.load(handle))\n"
    "with open('" + RESULTS_ARTIFACT_FILE + "', 'w', encoding='utf-8') as handle:\n"
    "    json.dump({'stages': rows}, handle, indent=2, sort_keys=True)\n"
)


def result_file_name(stage_id: str) -> str:
    """Per-stage result file uploaded by every stage job (observation contract)."""
    return f"{stage_id}{RESULT_FILE_SUFFIX}"


def _stage_script(step: Any, command: str | None) -> list[str]:
    """The job's ``script:`` — fixed scaffolding around the allow-listed command."""
    if step.tool_name.startswith(GATE_TOOL_PREFIX):
        # Control-plane orchestrated: no shell tool runs, exit 0 immediately.
        return ["echo 'orchestrated by ci-agent control plane'", "exit 0"]
    if command is None and step.command_template_id == CHECKOUT_TEMPLATE_ID:
        # GitLab runners fetch sources implicitly per job (GIT_STRATEGY);
        # the checkout stage is an explicit no-op marker in the stage graph.
        # The exit-code file is still written so the uniform after_script
        # result reporting reports passed/0.
        return [
            "echo 'checkout: sources fetched by the GitLab runner (GIT_STRATEGY)'",
            f'echo "0" > {EXIT_CODE_FILE}',
        ]
    return [
        "set +e",
        command or "",
        "code=$?",
        f'echo "$code" > {EXIT_CODE_FILE}',
        "exit $code",
    ]


def _stage_after_script(stage_id: str, *, gate: bool) -> list[str]:
    """Emit the per-stage result JSON even when the job failed."""
    if gate:
        return [
            "printf "
            '\'{"stage_id": "%s", "status": "passed", "exit_code": 0}\\n\' '
            f"'{stage_id}' > {result_file_name(stage_id)}"
        ]
    return [
        _AFTER_SCRIPT_TEMPLATE.format(
            exit_code_file=EXIT_CODE_FILE,
            stage_id=stage_id,
            result_file=result_file_name(stage_id),
        )
    ]


def _stage_job(step: Any, command: str | None) -> dict[str, Any]:
    """Build one stage job from a ResolvedStep + its allow-listed command."""
    stage_id = step.stage_id
    gate = step.tool_name.startswith(GATE_TOOL_PREFIX)
    job: dict[str, Any] = {
        "stage": stage_id,
        "script": _stage_script(step, command),
        "after_script": _stage_after_script(stage_id, gate=gate),
        "artifacts": {
            "when": "always",
            "paths": [result_file_name(stage_id)],
        },
    }
    if step.container_image:
        job["image"] = step.container_image
    if stage_id in REPORT_UPLOAD_STAGES:
        # Raw scanner/builder reports for control-plane parsing (Batch 6/7
        # convention): uploaded even when the scan FAILED (fail-closed review
        # needs the failing tool's output, not a silent gap).
        job["artifacts"]["paths"].extend(sorted(REPORT_UPLOAD_STAGES[stage_id]))
    return job


def _results_job(stage_job_names: list[str]) -> dict[str, Any]:
    """The always-run results job: merges per-stage results into one artifact."""
    return {
        "stage": RESULTS_JOB_NAME,
        "when": "always",
        "needs": stage_job_names,
        "script": [f"python3 - <<'PY'\n{_RESULTS_PY_SCRIPT}PY"],
        "artifacts": {"when": "always", "paths": [RESULTS_ARTIFACT_FILE]},
    }


def compile_to_gitlab_ci(
    plan: ExecutionPlan,
    registry: CommandTemplateRegistry | None = None,
) -> str:
    """Compile ``plan`` into ``.gitlab-ci.yml`` text.

    Every ``script:`` command comes verbatim from the (shared) command
    template registry; unknown command template ids fail compilation
    immediately. The generated YAML is round-trip validated before being
    returned.
    """
    registry = registry or CommandTemplateRegistry()

    ordered_stage_ids = [step.stage_id for step in plan.resolved_steps]  # topological

    pipeline: dict[str, Any] = {
        # Explicit control: only API-triggered pipelines run (NOTES.md).
        "workflow": {"rules": [{"if": WORKFLOW_RULE}]},
        "stages": [*ordered_stage_ids, RESULTS_JOB_NAME],
    }

    stage_job_names: list[str] = []
    for step in plan.resolved_steps:
        if step.tool_name.startswith(GATE_TOOL_PREFIX):
            command: str | None = None
        else:
            command = registry.get_command(step.command_template_id)
        pipeline[step.stage_id] = _stage_job(step, command)
        stage_job_names.append(step.stage_id)

    pipeline[RESULTS_JOB_NAME] = _results_job(stage_job_names)

    text = str(yaml.safe_dump(pipeline, sort_keys=False, default_flow_style=False))
    # Round-trip validation before returning (batch requirement).
    reparsed = yaml.safe_load(text)
    if not isinstance(reparsed, dict) or "stages" not in reparsed:  # pragma: no cover
        raise ValueError("compiled .gitlab-ci.yml failed round-trip validation")
    if len(reparsed["stages"]) != len(ordered_stage_ids) + 1:  # pragma: no cover
        raise ValueError("compiled .gitlab-ci.yml stage list mismatch")
    # Section 7.3: the compiled pipeline must NEVER reference credential
    # contexts — the secrets context appearing anywhere is a hard failure
    # (same enforced check as the GitHub compiler).
    if "secrets." in text:
        raise ValueError(
            "compiled pipeline references the secrets context — the agent "
            "never injects credentials into pipeline steps (Section 7.3)"
        )
    return text
