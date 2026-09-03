"""Unit tests for the GitLab CI compiler (Batch 8, Task A)."""

from __future__ import annotations

import pytest
import yaml

from ci_agent.adapters.gitlab_ci.compiler import (
    RESULTS_ARTIFACT_FILE,
    RESULTS_JOB_NAME,
    compile_to_gitlab_ci,
    result_file_name,
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
        self.yaml_text = compile_to_gitlab_ci(build_plan())
        self.pipeline = yaml.safe_load(self.yaml_text)

    def test_is_valid_yaml_round_trip(self) -> None:
        assert isinstance(self.pipeline, dict)
        assert "stages" in self.pipeline
        assert yaml.safe_dump(self.pipeline)  # re-dump works

    def test_stages_list_preserves_plan_order_plus_results(self) -> None:
        assert self.pipeline["stages"] == [
            "checkout",
            "format_lint",
            "sast",
            "unit_tests",
            "secret_scan",
            "dependency_scan",
            "policy_gate",
            RESULTS_JOB_NAME,
        ]

    def test_one_job_per_stage_plus_results(self) -> None:
        jobs = {key for key in self.pipeline if key not in ("stages", "workflow")}
        assert jobs == {
            "checkout",
            "format_lint",
            "sast",
            "unit_tests",
            "secret_scan",
            "dependency_scan",
            "policy_gate",
            RESULTS_JOB_NAME,
        }

    def test_each_job_assigned_to_its_stage(self) -> None:
        for stage_id in ("checkout", "format_lint", "sast"):
            assert self.pipeline[stage_id]["stage"] == stage_id

    def test_only_api_triggered_pipelines_run(self) -> None:
        rules = self.pipeline["workflow"]["rules"]
        assert rules == [{"if": '$CI_PIPELINE_SOURCE == "api"'}]

    def test_commands_come_verbatim_from_the_registry(self) -> None:
        assert "ruff check ." in self.pipeline["format_lint"]["script"]
        assert "bandit -r . -f json -o bandit-report.json" in self.pipeline["sast"]["script"]

    def test_exit_code_capture_scaffolding(self) -> None:
        script = self.pipeline["format_lint"]["script"]
        assert script[0] == "set +e"
        assert 'echo "$code" > ci-agent-exit-code' in script
        assert script[-1] == "exit $code"

    def test_gate_stages_exit_zero_without_tool_commands(self) -> None:
        script = self.pipeline["policy_gate"]["script"]
        assert script == ["echo 'orchestrated by ci-agent control plane'", "exit 0"]
        assert "bandit" not in " ".join(script)

    def test_checkout_stage_is_explicit_noop_marker(self) -> None:
        script = self.pipeline["checkout"]["script"]
        assert any("GIT_STRATEGY" in line for line in script)
        # The exit-code file is still written so the result reports passed/0.
        assert 'echo "0" > ci-agent-exit-code' in script

    def test_container_image_injected_at_job_level(self) -> None:
        assert self.pipeline["format_lint"]["image"] == "python:3.11-slim"
        assert "image" not in self.pipeline["checkout"]

    def test_every_stage_job_uploads_result_artifact_always(self) -> None:
        for stage_id in ("checkout", "format_lint", "sast", "policy_gate"):
            artifacts = self.pipeline[stage_id]["artifacts"]
            assert artifacts["when"] == "always"
            assert result_file_name(stage_id) in artifacts["paths"]

    def test_scan_stages_upload_raw_reports(self) -> None:
        paths = self.pipeline["sast"]["artifacts"]["paths"]
        assert "bandit-report.json" in paths
        secret_paths = self.pipeline["secret_scan"]["artifacts"]["paths"]
        assert "gitleaks-report.json" in secret_paths

    def test_after_script_writes_result_json(self) -> None:
        after = self.pipeline["format_lint"]["after_script"]
        joined = " ".join(after)
        assert "format_lint.result.json" in joined
        assert "ci-agent-exit-code" in joined


class TestResultsJob:
    def setup_method(self) -> None:
        self.yaml_text = compile_to_gitlab_ci(build_plan())
        self.pipeline = yaml.safe_load(self.yaml_text)

    def test_results_job_always_runs_and_needs_all_stages(self) -> None:
        results = self.pipeline[RESULTS_JOB_NAME]
        assert results["when"] == "always"
        assert set(results["needs"]) == {
            "checkout",
            "format_lint",
            "sast",
            "unit_tests",
            "secret_scan",
            "dependency_scan",
            "policy_gate",
        }
        assert results["stage"] == RESULTS_JOB_NAME

    def test_results_job_merges_result_files_into_artifact(self) -> None:
        results = self.pipeline[RESULTS_JOB_NAME]
        assert RESULTS_ARTIFACT_FILE in results["artifacts"]["paths"]
        assert "*.result.json" in results["script"][0]
        assert results["script"][0].startswith("python3 - <<'PY'")


class TestGuards:
    def test_unknown_command_template_fails_compilation(self) -> None:
        plan = build_plan()
        bad = plan.model_copy(
            update={
                "resolved_steps": [
                    step.model_copy(
                        update={
                            "tool_name": "mystery",
                            "command_template_id": "nope.nope",
                        }
                    )
                    for step in plan.resolved_steps
                ]
            }
        )
        from ci_agent.adapters.github_actions.command_template_registry import (
            UnknownCommandTemplateError,
        )

        with pytest.raises(UnknownCommandTemplateError):
            compile_to_gitlab_ci(bad)

    def test_secrets_context_reference_is_a_hard_failure(self) -> None:
        import ci_agent.adapters.gitlab_ci.compiler as compiler_module

        original = compiler_module._stage_script

        def _leaky(step, command):  # type: ignore[no-untyped-def]
            return ["echo 'secrets.SOMETHING'"]

        compiler_module._stage_script = _leaky  # type: ignore[assignment]
        try:
            with pytest.raises(ValueError, match="secrets"):
                compile_to_gitlab_ci(build_plan())
        finally:
            compiler_module._stage_script = original  # type: ignore[assignment]

    def test_result_file_naming_convention(self) -> None:
        assert result_file_name("sast") == "sast.result.json"
