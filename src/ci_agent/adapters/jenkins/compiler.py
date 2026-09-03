"""Compile an ExecutionPlan into a declarative Jenkinsfile (Batch 8, Task B).

Mirrors the other adapters' documented discipline (NOTES.md):

- **One ``stage()`` block per ResolvedStep**, in the plan's topological
  (Planner) order — declarative pipelines execute ``stages`` sequentially,
  which preserves the dependency order exactly (our plans are one job per
  stage).
- **Allow-listed commands only**: every ``sh`` step is a verbatim lookup
  from the SHARED command template registry (Batch 4 — the registry is
  runner-agnostic; there is deliberately NO Jenkins-specific registry).
  Unknown ids fail compilation immediately.
- **Gate stages (``internal.*`` tool names)** emit ``sh 'exit 0'`` — they
  are orchestrated by the control plane, not by a tool.
- **NO ci-agent-results artifact step**: unlike GitHub/GitLab, result
  collection for Jenkins is POLL-based (the Jenkins build result API),
  because Jenkins webhooks are configured at the Jenkins server level, not
  in the compiled pipeline (documented in NOTES.md and the adapter's module
  docstring). The compiled Jenkinsfile therefore contains only the pipeline
  stages — no summary job, no artifact upload.
- The generated text is structurally validated (declarative skeleton,
  balanced braces, one stage per step) before being returned.
"""

from __future__ import annotations

from typing import Any

from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.github_actions.compiler import (
    CHECKOUT_TEMPLATE_ID,
    GATE_TOOL_PREFIX,
)
from ci_agent.core.models.execution_plan import ExecutionPlan

GATE_STEP = "exit 0"
# Double quotes INSIDE the single-quoted Groovy sh string — safe as-is.
CHECKOUT_STEP = 'echo "checkout: sources fetched by the Jenkins SCM configuration"'


def _groovy_single_quoted(text: str) -> str:
    """Escape ``text`` for a single-quoted Groovy string (``sh '...'``).

    Backslashes first, then single quotes — commands like
    ``docker inspect --format '{{.Id}}'`` embed single quotes and must not
    break out of the sh string.
    """
    return text.replace("\\", "\\\\").replace("'", "\\'")


def _stage_block(step: Any, command: str | None) -> str:
    """One declarative ``stage('id') { steps { sh '...' } }`` block."""
    stage_id = step.stage_id
    if step.tool_name.startswith(GATE_TOOL_PREFIX):
        # Control-plane orchestrated: no tool runs; the stage exists so the
        # build log reflects the plan's stage graph.
        sh = GATE_STEP
    elif command is None and step.command_template_id == CHECKOUT_TEMPLATE_ID:
        # Jenkins checks sources out via the job's SCM configuration; the
        # checkout stage is an explicit marker in the stage graph.
        sh = CHECKOUT_STEP
    else:
        sh = _groovy_single_quoted(command or "")
    return (
        f"        stage('{stage_id}') {{\n"
        f"            steps {{\n"
        f"                sh '{sh}'\n"
        f"            }}\n"
        f"        }}\n"
    )


def _validate_jenkinsfile(text: str, stage_count: int) -> None:
    """Structural validation before returning (batch requirement)."""
    first_code_line = next(
        (line for line in text.splitlines() if line.strip() and not line.startswith("//")),
        "",
    )
    if first_code_line != "pipeline {":
        raise ValueError("compiled Jenkinsfile must start with the declarative 'pipeline {'")
    if text.count("{") != text.count("}"):
        raise ValueError("compiled Jenkinsfile has unbalanced braces")
    emitted_stages = text.count("stage('")
    if emitted_stages != stage_count:
        raise ValueError(
            "compiled Jenkinsfile stage count does not match the plan "
            f"({emitted_stages} != {stage_count})"
        )
    # Section 7.3: the compiled pipeline must NEVER reference credential
    # mechanisms — withCredentials/withSecrets appearing anywhere is a hard
    # compile failure (Jenkins analogue of the GitHub/GitLab secrets guard).
    for marker in ("withCredentials", "withSecrets", "secrets."):
        if marker in text:
            raise ValueError(
                f"compiled Jenkinsfile references {marker!r} — the agent never "
                "injects credentials into pipeline steps (Section 7.3)"
            )


def compile_to_jenkinsfile(
    plan: ExecutionPlan,
    registry: CommandTemplateRegistry | None = None,
) -> str:
    """Compile ``plan`` into declarative Jenkinsfile text.

    Every ``sh`` command comes verbatim from the (shared) command template
    registry; unknown command template ids fail compilation immediately.
    """
    registry = registry or CommandTemplateRegistry()

    blocks: list[str] = []
    for step in plan.resolved_steps:
        if step.tool_name.startswith(GATE_TOOL_PREFIX):
            command: str | None = None
        else:
            command = registry.get_command(step.command_template_id)
        blocks.append(_stage_block(step, command))

    text = (
        "// ci-agent compiled pipeline (declarative) — result collection is\n"
        "// poll-based via the Jenkins build result API (NOTES.md).\n"
        "pipeline {\n"
        "    agent any\n"
        "    stages {\n" + "".join(blocks) + "    }\n"
        "}\n"
    )
    _validate_jenkinsfile(text, stage_count=len(plan.resolved_steps))
    return text
