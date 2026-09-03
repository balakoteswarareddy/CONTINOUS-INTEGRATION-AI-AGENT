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


# --------------------------------------------------------------------------
# Batch 7: Phase B compilation (Section 5.2 nine-stage supply-chain flow).
# --------------------------------------------------------------------------

PHASE_B_STAGES = [
    ("checkout", "git", "2.43", None, "checkout.default", []),
    (
        "merge_decision",
        "internal.merge_decision",
        "internal",
        None,
        "internal.merge_decision",
        ["checkout"],
    ),
    (
        "full_build",
        "build",
        "1.2.1",
        "python:3.11-slim",
        "build.default.python",
        ["merge_decision"],
    ),
    (
        "integration_tests",
        "pytest",
        "8.2.0",
        "python:3.11-slim",
        "test.integration.python",
        ["full_build"],
    ),
    (
        "coverage_gate",
        "internal.coverage_gate",
        "internal",
        None,
        "internal.coverage_gate",
        ["integration_tests"],
    ),
    (
        "container_build",
        "docker",
        "27.3.1",
        "docker:27.3.1-cli",
        "container.build",
        ["coverage_gate"],
    ),
    ("sbom_generate", "syft", "1.18.1", "anchore/syft:v1.18.1", "sbom.syft", ["container_build"]),
    ("image_scan", "trivy", "0.58.0", "aquasec/trivy:0.58.0", "scan.trivy", ["sbom_generate"]),
    (
        "sign_attest",
        "cosign",
        "2.4.1",
        "sigstore/cosign:v2.4.1",
        "sign.cosign",
        ["image_scan"],
    ),
    ("publish", "docker", "27.3.1", "docker:27.3.1-cli", "publish.oci", ["sign_attest"]),
    (
        "record_evidence",
        "internal.record_evidence",
        "internal",
        None,
        "internal.record_evidence",
        ["publish"],
    ),
]


def build_phase_b_plan() -> ExecutionPlan:
    """Phase A terminal gate + the nine Phase B stages (one combined plan)."""
    return ExecutionPlan(
        run_id="run-b7",
        pipeline_spec_ref="sha256:def",
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
            for sid, tool, version, image, template, deps in PHASE_B_STAGES
        ],
    )


class TestPhaseBCompilation:
    def setup_method(self) -> None:
        self.yaml_text = compile_to_github_actions(build_phase_b_plan())
        self.workflow = yaml.safe_load(self.yaml_text)

    def test_phase_b_jobs_come_after_phase_a_jobs(self) -> None:
        job_ids = list(self.workflow["jobs"])
        assert job_ids.index("stage-checkout") < job_ids.index("stage-full_build")
        assert job_ids.index("stage-merge_decision") < job_ids.index("stage-full_build")
        assert job_ids.index("stage-record_evidence") < job_ids.index("ci-agent-results")

    def test_full_build_needs_chain_reaches_phase_a_terminal_gate(self) -> None:
        """needs: chains Phase B to Phase A's terminal gate job."""
        assert self.workflow["jobs"]["stage-full_build"]["needs"] == ["stage-merge_decision"]

    def test_one_job_per_phase_b_stage(self) -> None:
        for stage_id, *_ in PHASE_B_STAGES:
            job_id = job_id_for_stage(stage_id)
            assert job_id in self.workflow["jobs"]
            assert self.workflow["jobs"][job_id]["name"] == stage_id

    def test_phase_b_report_uploads(self) -> None:
        steps = self.workflow["jobs"]["stage-image_scan"]["steps"]
        uploads = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact")]
        assert any(s["with"]["name"] == "ci-agent-scan-image_scan" for s in uploads)
        sign_steps = self.workflow["jobs"]["stage-sign_attest"]["steps"]
        assert any(s.get("with", {}).get("name") == "ci-agent-scan-sign_attest" for s in sign_steps)

    def test_publish_env_var_injected_not_secrets(self) -> None:
        assert self.workflow["env"]["CI_AGENT_PUBLISH_REF"] == "${{ vars.CI_AGENT_PUBLISH_REF }}"

    def test_never_injects_secrets_context(self) -> None:
        assert "secrets." not in self.yaml_text

    def test_phase_b_commands_are_verbatim_registry_values(self) -> None:
        registry = CommandTemplateRegistry()
        for stage_id, tool, _v, _i, template, _d in PHASE_B_STAGES:
            if tool.startswith("internal.") or stage_id == "checkout":
                continue
            job = self.workflow["jobs"][job_id_for_stage(stage_id)]
            tool_step = next(s for s in job["steps"] if s.get("id") == "tool" and "run" in s)
            command_line = tool_step["run"].splitlines()[1]
            assert command_line == registry.get_command(template)
