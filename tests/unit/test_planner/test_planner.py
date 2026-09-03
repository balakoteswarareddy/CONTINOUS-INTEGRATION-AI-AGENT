"""Unit tests for the Planner (Batch 3, Task B)."""

from __future__ import annotations

import pytest

from ci_agent.core.models.common import PolicyDecision
from ci_agent.core.models.execution_plan import RetryPolicy
from ci_agent.core.models.pipeline_spec import PipelineSpec
from ci_agent.core.models.policy_spec import PolicySpec
from ci_agent.planner.planner import Planner, TemplateMismatchError, UnapprovedToolError
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.resolver.project_profile import ProjectProfile


@pytest.fixture()
def registry() -> TemplateRegistry:
    return TemplateRegistry()


@pytest.fixture()
def planner(registry: TemplateRegistry, approved_policy_spec: PolicySpec) -> Planner:
    return Planner(template_registry=registry, policy_spec=approved_policy_spec)


class TestPlanGeneration:
    def test_builds_valid_plan_for_python_stack(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        plan = planner.build_execution_plan(
            python_project_profile,
            phase_a_pipeline_spec,
            "1.0.0",
            run_id="run-42",
        )

        assert plan.run_id == "run-42"
        assert plan.pipeline_spec_ref.startswith("sha256:")
        assert len(plan.resolved_steps) == 9

    def test_dependency_order_is_respected(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        plan = planner.build_execution_plan(
            python_project_profile, phase_a_pipeline_spec, "1.0.0", run_id="run-1"
        )

        position = {step.stage_id: index for index, step in enumerate(plan.resolved_steps)}
        deps = {stage.id: stage.depends_on for stage in phase_a_pipeline_spec.stages}
        for stage_id, dependencies in deps.items():
            for dep in dependencies:
                assert position[dep] < position[stage_id], f"{dep} must precede {stage_id}"
        assert plan.resolved_steps[0].stage_id == "checkout"
        assert plan.resolved_steps[-1].stage_id == "merge_decision"

    def test_step_contents_match_template(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        plan = planner.build_execution_plan(
            python_project_profile, phase_a_pipeline_spec, "1.0.0", run_id="run-1"
        )

        by_stage = {step.stage_id: step for step in plan.resolved_steps}
        lint = by_stage["format_lint"]
        assert lint.tool_name == "ruff"
        assert lint.tool_version == "0.6.0"
        assert lint.container_image == "python:3.11-slim"
        assert lint.command_template_id == "lint.ruff"
        assert lint.timeout_seconds == 300
        assert lint.retry_policy.max_retries == 0
        assert lint.retry_policy.retryable is False

        checkout = by_stage["checkout"]
        assert checkout.container_image is None
        assert checkout.retry_policy == RetryPolicy(max_retries=2, retryable=True)

    def test_gate_steps_are_internal_steps_without_images(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        plan = planner.build_execution_plan(
            python_project_profile, phase_a_pipeline_spec, "1.0.0", run_id="run-1"
        )

        by_stage = {step.stage_id: step for step in plan.resolved_steps}
        for gate in ("policy_gate", "human_approval", "merge_decision"):
            step = by_stage[gate]
            assert step.tool_name == f"internal.{gate}"
            assert step.container_image is None
            assert step.tool_version == "internal"

    def test_pipeline_spec_ref_is_stable_content_hash(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        ref1 = Planner.pipeline_spec_hash(phase_a_pipeline_spec)
        ref2 = Planner.pipeline_spec_hash(phase_a_pipeline_spec)
        assert ref1 == ref2

        tweaked = phase_a_pipeline_spec.model_copy(update={"thresholds": {"coverage_percent": 90}})
        assert Planner.pipeline_spec_hash(tweaked) != ref1

    def test_step_ids_are_unique(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        plan = planner.build_execution_plan(
            python_project_profile, phase_a_pipeline_spec, "1.0.0", run_id="run-1"
        )

        ids = [step.step_id for step in plan.resolved_steps]
        assert len(ids) == len(set(ids))


def policy_with_tool_versions(versions: dict[str, str]) -> PolicySpec:
    """The approved policy fixture with a specific approved_tool_versions map."""
    return PolicySpec(
        policy_version="1.0.0",
        identity_policy={
            "allowed_repositories": ["example-org/*"],
            "allowed_branches": ["main", "release/*", "feature/*"],
            "allowed_identities": [],
        },
        tool_policy={
            "approved_tool_versions": versions,
            "approved_images": ["python:3.11-slim"],
            "forbidden_tools": [],
        },
        security_policy={
            "severity_thresholds": {"critical": 0, "high": 0, "medium": 5, "low": 20},
            "require_secret_scan": True,
            "require_sca": True,
        },
        build_policy={
            "allowed_base_images": ["python:3.11-slim"],
            "allowed_egress_domains": ["pypi.org"],
            "max_timeout_seconds": 3600,
        },
        artifact_policy={
            "require_sbom": True,
            "sbom_format": "spdx",
            "require_signing": True,
            "registry_allowlist": ["ghcr.io/example-org"],
        },
        approval_policy={
            "require_human_approval_for": ["high", "regulated"],
            "approver_groups": ["security-champions"],
        },
        ai_policy={
            "allowed_model_providers": [],
            "allowed_data_classification": ["public"],
            "require_human_override": True,
        },
    )


ALL_PYTHON_TOOLS: dict[str, str] = {
    "git": "2.43",
    "ruff": "0.6.0",
    "bandit": "1.7.9",
    "pytest": "8.2.0",
    "gitleaks": "8.18.2",
    "pip-audit": "2.7.2",
}


class TestPolicyEnforcement:
    def test_unapproved_tool_raises_listing_all_offenders(
        self,
        registry: TemplateRegistry,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        planner = Planner(template_registry=registry, policy_spec=policy_with_tool_versions({}))

        with pytest.raises(UnapprovedToolError) as excinfo:
            planner.build_execution_plan(
                python_project_profile, phase_a_pipeline_spec, "1.0.0", run_id="run-1"
            )

        message = str(excinfo.value)
        for tool in ("ruff", "bandit", "pytest", "gitleaks", "pip-audit"):
            assert tool in message
        # internal gates are exempt from tool approval
        assert "internal." not in message

    def test_wrong_tool_version_raises(
        self,
        registry: TemplateRegistry,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        versions = dict(ALL_PYTHON_TOOLS)
        versions["ruff"] = "0.1.0"  # template pins 0.6.0
        planner = Planner(
            template_registry=registry, policy_spec=policy_with_tool_versions(versions)
        )

        with pytest.raises(UnapprovedToolError, match=r"ruff@0\.6\.0"):
            planner.build_execution_plan(
                python_project_profile, phase_a_pipeline_spec, "1.0.0", run_id="run-1"
            )

    def test_policy_version_mismatch_raises(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        with pytest.raises(ValueError, match="does not match governed policy version"):
            planner.build_execution_plan(
                python_project_profile, phase_a_pipeline_spec, "9.9.9", run_id="run-1"
            )

    def test_unknown_stack_raises(
        self, planner: Planner, phase_a_pipeline_spec: PipelineSpec
    ) -> None:
        profile = rust_profile()

        with pytest.raises(KeyError, match=r"rust"):
            planner.build_execution_plan(profile, phase_a_pipeline_spec, "1.0.0", run_id="run-1")

    def test_pipeline_stage_missing_from_template_raises(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        spec_payload = phase_a_pipeline_spec.model_dump(mode="python")
        spec_payload["stages"] = [
            *spec_payload["stages"],
            {"id": "deploy", "name": "Deploy", "depends_on": ["merge_decision"]},
        ]
        extra_stage = PipelineSpec(**spec_payload)

        with pytest.raises(TemplateMismatchError, match="deploy"):
            planner.build_execution_plan(
                python_project_profile, extra_stage, "1.0.0", run_id="run-1"
            )

    def test_extra_template_stages_not_in_spec_are_not_planned(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        """PipelineSpec decides WHAT runs; unused template stages are not planned."""
        spec_payload = phase_a_pipeline_spec.model_dump(mode="python")
        spec_payload["stages"] = [
            stage for stage in spec_payload["stages"] if stage["id"] != "human_approval"
        ]
        # Rewire merge_decision to depend on policy_gate directly.
        for stage in spec_payload["stages"]:
            stage["depends_on"] = [d for d in stage["depends_on"] if d != "human_approval"]
        trimmed = PipelineSpec(**spec_payload)

        plan = planner.build_execution_plan(
            python_project_profile, trimmed, "1.0.0", run_id="run-1"
        )

        assert "human_approval" not in {step.stage_id for step in plan.resolved_steps}


class TestComposition:
    def test_planner_output_feeds_pdp_input(
        self,
        planner: Planner,
        python_project_profile: ProjectProfile,
        phase_a_pipeline_spec: PipelineSpec,
    ) -> None:
        """Planner and PDP stay separate but composable (Section 4.2 component table)."""
        from ci_agent.policy.models import PolicyInputFacts

        plan = planner.build_execution_plan(
            python_project_profile, phase_a_pipeline_spec, "1.0.0", run_id="run-9"
        )

        # The plan must serialize cleanly into the PDP's input facts.
        facts = PolicyInputFacts(
            project_profile=python_project_profile.model_dump(mode="json"),
            pipeline_spec=phase_a_pipeline_spec.model_dump(mode="json"),
            proposed_execution_plan=plan.model_dump(mode="json"),
            stage_id="plan_approval",
            run_id="run-9",
        )
        assert facts.proposed_execution_plan is not None
        assert facts.proposed_execution_plan["run_id"] == "run-9"
        assert PolicyDecision.PASS.value in {"pass", "fail", "waived"}


def rust_profile() -> ProjectProfile:
    return ProjectProfile(
        project_id="x",
        business_criticality="low",
        data_sensitivity="public",
        risk_tier="low",
        repo_structure="single_repo",
        language_stack="rust",  # intentionally no template
        runner="linux",
        secret_storage="github_actions_secrets",
        coverage_requirement=60.0,
        artifact_repository="github_packages",
        testing_strategy="unit",
        execution_location="github_hosted",
        policy_version_pinned="1.0.0",
        raw_intake_answers={},
    )
