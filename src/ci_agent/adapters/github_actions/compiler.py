"""Compile an ExecutionPlan into GitHub Actions workflow YAML (Batch 4, Task A).

Design decisions (documented in NOTES.md):
- **Jobs-per-stage**: one GitHub Actions job per ResolvedStep/stage, wired with
  ``needs:`` from the plan's dependency graph (``ResolvedStep.depends_on``).
  This was chosen over the single-job alternative because GitHub emits one
  Check Run per job named after the job, which the Execution Observer requires
  to map ``check_run`` webhook events to individual stage transitions.
- **Allow-listed commands only**: every ``run:`` command is a verbatim lookup
  from the command template registry (Section 7.3) — never free-form text.
  The exit-code capture scaffolding around each command is fixed, auditable
  boilerplate.
- **Structured results**: a final ``ci-agent-results`` job (``if: always()``)
  emits ``ci-agent-results.json`` (per-stage status + exit codes, from
  GitHub's own job results — not parsed logs) and uploads it as an artifact;
  the Observer reconciles from this structured evidence (Section 10).
- The generated YAML is round-trip validated (``yaml.safe_load``) before
  being returned.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.core.models.execution_plan import ExecutionPlan

WORKFLOW_FILE_NAME = "ci-agent-run.yml"
RESULTS_ARTIFACT_NAME = "ci-agent-results"
RESULTS_ARTIFACT_FILE = "ci-agent-results.json"

# Pinned runner scaffolding (reviewable constants — never dynamic strings).
RUNS_ON_LABEL = "ubuntu-latest"
CHECKOUT_ACTION = "actions/checkout@v4"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@v4"
CHECKOUT_TEMPLATE_ID = "checkout.default"
GATE_TOOL_PREFIX = "internal."
JOB_ID_PREFIX = "stage-"
SUMMARY_JOB_ID = "ci-agent-results"

# Batch 6: scan stages upload their raw tool report so the control plane can
# parse REAL findings (Security Evidence Service). Explicit table: stage_id ->
# {report file: tool_name}; the compiler emits one upload-artifact step per
# scan stage with artifact name ci-agent-scan-<stage_id>.
SCAN_STAGE_REPORT_FILES: dict[str, dict[str, str]] = {
    "sast": {"bandit-report.json": "bandit", "semgrep-report.json": "semgrep"},
    "secret_scan": {"gitleaks-report.json": "gitleaks"},
    "dependency_scan": {
        "pip-audit-report.json": "pip-audit",
        "npm-audit-report.json": "npm-audit",
    },
}

# Stages whose raw report is uploaded (scan stages + lint's eslint JSON).
REPORT_UPLOAD_STAGES: dict[str, dict[str, str]] = {
    **SCAN_STAGE_REPORT_FILES,
    "format_lint": {"eslint-report.json": "eslint"},
}

SCAN_ARTIFACT_NAME_PREFIX = "ci-agent-scan-"


def scan_artifact_name(stage_id: str) -> str:
    return f"{SCAN_ARTIFACT_NAME_PREFIX}{stage_id}"


# GitHub job result values (needs.<job>.result) -> our StageStatus vocabulary.
# Explicit, reviewable mapping table — not inferred at runtime (batch DoD).
GITHUB_JOB_RESULT_TO_STAGE_STATUS: dict[str, str] = {
    "success": "passed",
    "failure": "failed",
    "cancelled": "cancelled",
    "skipped": "skipped",
}


def job_id_for_stage(stage_id: str) -> str:
    """GitHub job id for a stage (ids must be [a-zA-Z0-9_-])."""
    return f"{JOB_ID_PREFIX}{stage_id}"


def stage_id_from_job_id(job_id: str) -> str:
    """Inverse of :func:`job_id_for_stage`."""
    if not job_id.startswith(JOB_ID_PREFIX):
        raise ValueError(f"Not a ci-agent stage job id: {job_id!r}")
    return job_id[len(JOB_ID_PREFIX) :]


def _tool_step(command: str, stage_id: str, tool_name: str) -> dict[str, Any]:
    """A shell step running the allow-listed command with exit-code capture.

    The scaffolding around the command (``set +e`` / ``$GITHUB_OUTPUT`` /
    ``exit``) is fixed and auditable; the command itself is the verbatim
    registry value.
    """
    return {
        "name": f"[{stage_id}] {tool_name}",
        "id": "tool",
        "run": (
            "set +e\n"
            f"{command}\n"
            "code=$?\n"
            'echo "exit_code=$code" >> "$GITHUB_OUTPUT"\n'
            "exit $code\n"
        ),
    }


def _stage_job(step: Any, command: str | None, needs: list[str]) -> dict[str, Any]:
    """Build one stage job from a ResolvedStep + its allow-listed command."""
    stage_id = step.stage_id
    job: dict[str, Any] = {
        "name": stage_id,  # check_run.name == stage_id for Observer correlation
        "runs-on": RUNS_ON_LABEL,
        "needs": needs,
        "outputs": {"exit_code": "${{ steps.tool.outputs.exit_code }}"},
        "steps": [],
    }
    if step.container_image:
        job["container"] = {"image": step.container_image}

    if step.tool_name.startswith(GATE_TOOL_PREFIX):
        # See compile_to_github_actions: control-plane orchestrated stage.
        job["steps"].append(
            {
                "name": f"[{stage_id}] {step.tool_name}",
                "id": "tool",
                "run": (
                    'echo "orchestrated by ci-agent control plane"\n'
                    'echo "exit_code=0" >> "$GITHUB_OUTPUT"\n'
                ),
            }
        )
    elif command is None and step.command_template_id == CHECKOUT_TEMPLATE_ID:
        # Native handling: the pinned checkout action, not a shell command.
        job["steps"].append(
            {"name": f"[{stage_id}] {step.tool_name}", "id": "tool", "uses": CHECKOUT_ACTION}
        )
    else:
        job["steps"].append(_tool_step(command or "", stage_id, step.tool_name))
    if stage_id in REPORT_UPLOAD_STAGES:
        # Upload the raw report for control-plane parsing (Batch 6). if/always
        # so a FAILING scan still uploads its findings for fail-closed review.
        report_paths = " ".join(REPORT_UPLOAD_STAGES[stage_id])
        job["steps"].append(
            {
                "name": f"upload scan report [{stage_id}]",
                "if": "always()",
                "uses": UPLOAD_ARTIFACT_ACTION,
                "with": {
                    "name": scan_artifact_name(stage_id),
                    "path": report_paths,
                    "if-no-files-found": "ignore",
                },
            }
        )
    return job


_SUMMARY_PY_SCRIPT = (
    "import json, os\n"
    "needs = json.loads(os.environ['CI_AGENT_NEEDS'])\n"
    "mapping = json.loads(os.environ['CI_AGENT_STATUS_MAP'])\n"
    "stages = json.loads(os.environ['CI_AGENT_STAGES'])\n"
    "rows = []\n"
    "for stage_id in stages:\n"
    "    job = needs['" + JOB_ID_PREFIX + "' + stage_id]\n"
    "    status = mapping.get(job.get('result'), 'failed')\n"
    "    raw_code = (job.get('outputs') or {}).get('exit_code')\n"
    "    exit_code = int(raw_code) if raw_code not in (None, '') else None\n"
    "    rows.append({'stage_id': stage_id, 'status': status, 'exit_code': exit_code})\n"
    "with open('" + RESULTS_ARTIFACT_FILE + "', 'w', encoding='utf-8') as handle:\n"
    "    json.dump({'stages': rows}, handle, indent=2, sort_keys=True)\n"
)


def _summary_job() -> dict[str, Any]:
    """The always-run results job: emits the structured results artifact."""
    return {
        "name": SUMMARY_JOB_ID,
        "runs-on": RUNS_ON_LABEL,
        "needs": [],  # filled in by compile_to_github_actions
        "if": "always()",
        "steps": [
            {
                "name": "emit structured results",
                "id": "results",
                "env": {"CI_AGENT_NEEDS": "${{ toJson(needs) }}"},
                "run": f"python3 - <<'PY'\n{_SUMMARY_PY_SCRIPT}PY\n",
            },
            {
                "name": "upload results artifact",
                "uses": UPLOAD_ARTIFACT_ACTION,
                "with": {"name": RESULTS_ARTIFACT_NAME, "path": RESULTS_ARTIFACT_FILE},
            },
        ],
    }


def compile_to_github_actions(
    plan: ExecutionPlan,
    registry: CommandTemplateRegistry | None = None,
) -> str:
    """Compile ``plan`` into GitHub Actions workflow YAML text.

    Every ``run:`` command comes verbatim from the command template registry;
    unknown command template ids fail compilation immediately. The generated
    YAML is round-trip validated before being returned.
    """
    registry = registry or CommandTemplateRegistry()

    by_stage = {step.stage_id: step for step in plan.resolved_steps}
    ordered_stage_ids = [step.stage_id for step in plan.resolved_steps]  # topological (Planner)

    workflow: dict[str, Any] = {
        "name": "ci-agent-run",
        # Explicit control: dispatch happens via the workflow_dispatch API on
        # the dedicated ci-agent/<run_id> branch (rationale in NOTES.md).
        "on": {"workflow_dispatch": {}},
        # Least privilege: the workflow only checks out code and uploads its
        # own results artifact; the merge decision is posted via the GitHub
        # API with the adapter's own credential, not the workflow's token.
        "permissions": {"contents": "read"},
        "env": {
            "CI_AGENT_STAGES": json.dumps(ordered_stage_ids),
            "CI_AGENT_STATUS_MAP": json.dumps(GITHUB_JOB_RESULT_TO_STAGE_STATUS),
        },
        "jobs": {},
    }

    stage_job_ids: list[str] = []
    for stage_id in ordered_stage_ids:
        step = by_stage[stage_id]
        if step.tool_name.startswith(GATE_TOOL_PREFIX):
            # Control-flow stages are orchestrated by the control plane; they
            # have no shell command and never consult the registry.
            command: str | None = None
        else:
            command = registry.get_command(step.command_template_id)
        needs = [job_id_for_stage(dep) for dep in step.depends_on]
        workflow["jobs"][job_id_for_stage(stage_id)] = _stage_job(step, command, needs)
        stage_job_ids.append(job_id_for_stage(stage_id))

    summary = _summary_job()
    summary["needs"] = stage_job_ids
    workflow["jobs"][SUMMARY_JOB_ID] = summary

    text = str(yaml.safe_dump(workflow, sort_keys=False, default_flow_style=False))
    # Round-trip validation before returning (batch requirement).
    reparsed = yaml.safe_load(text)
    if not isinstance(reparsed, dict) or "jobs" not in reparsed:  # pragma: no cover - defensive
        raise ValueError("compiled workflow YAML failed round-trip validation")
    return text
