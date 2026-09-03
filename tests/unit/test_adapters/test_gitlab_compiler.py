"""GitLab CI compiler tests (Batch 8, Task B; Section 12)."""

from __future__ import annotations

import pytest
import yaml
from tests.unit.test_adapters.test_compiler import build_phase_b_plan, build_plan

from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.gitlab_ci.compiler import (
    PIPELINE_PATH,
    compile_to_gitlab_ci,
    job_name_for_stage,
)


class TestCompiledGitLabYaml:
    def setup_method(self) -> None:
        self.yaml_text = compile_to_gitlab_ci(build_plan())
        self.workflow = yaml.safe_load(self.yaml_text)

    def test_is_valid_yaml_round_trip(self) -> None:
        assert isinstance(self.workflow, dict)
        assert "stages" in self.workflow

    def test_one_job_per_stage(self) -> None:
        expected = [
            job_name_for_stage(s)
            for s in (
                "checkout",
                "format_lint",
                "sast",
                "unit_tests",
                "secret_scan",
                "dependency_scan",
                "policy_gate",
            )
        ]
        for job_key in expected:
            assert job_key in self.workflow

    def test_job_names_map_to_stages_for_correlation(self) -> None:
        job = self.workflow["stage-format_lint"]
        assert job["stage"] == "format_lint"

    def test_needs_graph_matches_plan_dependencies(self) -> None:
        assert self.workflow["stage-sast"]["needs"] == ["stage-format_lint"]
        assert self.workflow["stage-policy_gate"]["needs"] == [
            "stage-unit_tests",
            "stage-secret_scan",
            "stage-dependency_scan",
        ]

    def test_container_image_injected_per_job(self) -> None:
        assert self.workflow["stage-sast"]["image"] == "python:3.11-slim"
        assert "image" not in self.workflow["stage-checkout"]

    def test_scan_report_artifacts_always_uploaded(self) -> None:
        artifacts = self.workflow["stage-sast"]["artifacts"]
        assert artifacts["when"] == "always"
        assert "bandit-report.json" in artifacts["paths"]

    def test_commands_are_verbatim_registry_values(self) -> None:
        registry = CommandTemplateRegistry()
        script = self.workflow["stage-sast"]["script"]
        assert registry.get_command("sast.bandit") in script

    def test_gate_stage_is_control_plane_placeholder(self) -> None:
        script = self.workflow["stage-policy_gate"]["script"]
        assert any("orchestrated by ci-agent control plane" in line for line in script)

    def test_phase_b_stages_compile_with_upload_and_publish_var(self) -> None:
        workflow = yaml.safe_load(compile_to_gitlab_ci(build_phase_b_plan()))
        assert workflow["stage-image_scan"]["artifacts"]["paths"] == ["trivy-report.json"]
        assert workflow["variables"]["CI_AGENT_PUBLISH_REF"] == "$CI_AGENT_PUBLISH_REF"

    def test_never_references_credentials(self) -> None:
        assert "secrets." not in self.yaml_text
        assert "PRIVATE-TOKEN" not in self.yaml_text
        assert "glpat-" not in self.yaml_text

    def test_credential_shaped_content_is_refused(self) -> None:
        """The compiler's deny list rejects credential-shaped output."""
        poisoned_text = "deploy:\n  script: ['curl -H PRIVATE-TOKEN: x']"
        with pytest.raises(ValueError, match="credential-shaped"):
            raise_if_forbidden(poisoned_text)


def raise_if_forbidden(text: str) -> None:
    """Mirror the compiler's guard for direct testing of the deny list."""
    from ci_agent.adapters.gitlab_ci.compiler import _FORBIDDEN_FRAGMENTS

    for fragment in _FORBIDDEN_FRAGMENTS:
        if fragment in text:
            raise ValueError(
                f"compiled GitLab CI YAML references credential-shaped fragment "
                f"{fragment!r} — the agent never injects credentials (Section 7.3)"
            )


def test_pipeline_path_constant() -> None:
    assert PIPELINE_PATH == ".gitlab-ci.yml"
