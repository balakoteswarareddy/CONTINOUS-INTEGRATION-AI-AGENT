"""Unit tests for the GitHub Actions compiler (Batch 4, Task A)."""

from __future__ import annotations

import pytest
import yaml

from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.github_actions.compiler import (
    RESULTS_ARTIFACT_NAME,
    compile_to_github_actions,
    job_id_for_stage,
)
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy


def build_plan() -> ExecutionPlan:
    """A plan mirroring the python template's Phase A stages."""
    stages = [
        ("checkout", "git", "2.43", None, "checkout.default", []),
        ("format_lint", "ruff", "0.6.0", "python:3.11-slim", "lint.ruff", ["checkout"]),
        ("sast", "bandit", "1.7.9", "python:3.11-slim", "sast.bandit", ["format_lint"]),
        ("unit_tests", "pytest", "8.2.0", "python:3.11-slim", "tests.pytest", ["format_lint"]),
        ("secret_scan", "gitleaks", "8.18.2", "python:3.11-slim", "scan.gitleaks", ["sast"]),
        ("dependency_scan", "pip-audit", "2.7.2", "python:3.11-slim", "scan.pip-audit", ["sast"]),
        (
            "policy_gate",
            "internal.policy_gate",
            "internal",
            None,
            "internal.policy_gate",
            ["unit_tests", "secret_scan", "dependency_scan"],
        ),
    ]
    return ExecutionPlan(
        run_id="run-1",
        pipeline_spec_ref="sha256:abc",
        resolved_steps=[
            ResolvedStep(
                step_id=f"{sid}.{tool}",
                stage_id=sid,
                tool_name=tool,
                tool_version=version,
                container_image=image,
                command_template_id=template,
                timeout_seconds=300,
                retry_policy=RetryPolicy(),
                depends_on=deps,
            )
            for sid, tool, version, image, template, deps in stages
        ],
    )


class TestCompiledYaml:
    def setup_method(self) -> None:
        self.yaml_text = compile_to_github_actions(build_plan())
        self.workflow = yaml.safe_load(self.yaml_text)

    def test_is_valid_yaml_round_trip(self) -> None:
        assert isinstance(self.workflow, dict)
        assert "jobs" in self.workflow
        assert yaml.safe_dump(self.workflow)  # re-dump works

    def test_triggers_only_on_workflow_dispatch(self) -> None:
        assert list(self.workflow["on"].keys()) == ["workflow_dispatch"]

    def test_one_job_per_stage_plus_results(self) -> None:
        jobs = self.workflow["jobs"]
        assert set(jobs) == {
            "stage-checkout",
            "stage-format_lint",
            "stage-sast",
            "stage-unit_tests",
            "stage-secret_scan",
            "stage-dependency_scan",
            "stage-policy_gate",
            "ci-agent-results",
        }

    def test_job_names_equal_stage_ids_for_check_run_correlation(self) -> None:
        for job_id, job in self.workflow["jobs"].items():
            if job_id == "ci-agent-results":
                continue
            assert job["name"] == job_id.removeprefix("stage-")

    def test_needs_graph_matches_plan_dependencies(self) -> None:
        jobs = self.workflow["jobs"]
        assert jobs["stage-checkout"]["needs"] == []
        assert jobs["stage-format_lint"]["needs"] == ["stage-checkout"]
        assert set(jobs["stage-policy_gate"]["needs"]) == {
            "stage-unit_tests",
            "stage-secret_scan",
            "stage-dependency_scan",
        }

    def test_container_image_injected_at_job_level(self) -> None:
        lint_container = self.workflow["jobs"]["stage-format_lint"]["container"]
        assert lint_container == {"image": "python:3.11-slim"}
        assert "container" not in self.workflow["jobs"]["stage-checkout"]

    def test_checkout_uses_pinned_action_not_shell(self) -> None:
        steps = self.workflow["jobs"]["stage-checkout"]["steps"]
        assert steps[0]["uses"] == "actions/checkout@v4"
        assert "run" not in steps[0]

    def test_results_job_always_runs_and_uploads_artifact(self) -> None:
        results = self.workflow["jobs"]["ci-agent-results"]
        assert results["if"] == "always()"
        expected_needs = {
            job_id_for_stage(sid)
            for sid in (
                "checkout",
                "format_lint",
                "sast",
                "unit_tests",
                "secret_scan",
                "dependency_scan",
                "policy_gate",
            )
        }
        assert set(results["needs"]) == expected_needs
        upload = results["steps"][1]
        assert "upload-artifact" in upload["uses"]
        assert upload["with"]["name"] == RESULTS_ARTIFACT_NAME

    def test_step_names_embed_stage_id_for_observability(self) -> None:
        lint_steps = self.workflow["jobs"]["stage-format_lint"]["steps"]
        assert lint_steps[0]["name"] == "[format_lint] ruff"


class TestCommandAllowListEnforcement:
    def test_every_run_command_is_verbatim_from_registry(self) -> None:
        """No inline free-text commands: each run: block must be scaffold+registry."""
        registry = CommandTemplateRegistry()
        known_commands = {c for c in registry.known_ids and registry._templates.values() if c}
        plan = build_plan()
        workflow = yaml.safe_load(compile_to_github_actions(plan, registry))

        wrapper_lines = {
            "set +e",
            "code=$?",
            'echo "exit_code=$code" >> "$GITHUB_OUTPUT"',
            "exit $code",
            'echo "orchestrated by ci-agent control plane"',  # gate placeholder
            'echo "exit_code=0" >> "$GITHUB_OUTPUT"',  # gate placeholder output
        }
        for job_id, job in workflow["jobs"].items():
            if job_id == "ci-agent-results":
                continue  # its run: block is the results-emitter script, not a tool command
            for step in job["steps"]:
                script = step.get("run")
                if script is None:
                    continue
                lines = {line for line in script.strip().splitlines() if line.strip()}
                command_lines = lines - wrapper_lines
                if not command_lines:
                    continue  # gate placeholder step (no tool command)
                for line in command_lines:
                    assert line in known_commands, f"non-allow-listed command in workflow: {line!r}"

    def test_unknown_command_template_fails_compilation(self) -> None:
        from ci_agent.adapters.github_actions.command_template_registry import (
            UnknownCommandTemplateError,
        )

        plan = build_plan()
        mutated = plan.model_dump()
        mutated["resolved_steps"][1]["command_template_id"] = "deploy.produce"
        plan = ExecutionPlan(**mutated)

        with pytest.raises(UnknownCommandTemplateError, match=r"deploy\.produce"):
            compile_to_github_actions(plan)

    def test_gate_steps_have_no_container_and_are_placeholders(self) -> None:
        workflow = yaml.safe_load(compile_to_github_actions(build_plan()))
        gate_job = workflow["jobs"]["stage-policy_gate"]
        assert "container" not in gate_job
        assert "orchestrated by ci-agent control plane" in gate_job["steps"][0]["run"]
