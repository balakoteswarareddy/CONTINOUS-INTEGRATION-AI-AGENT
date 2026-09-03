"""Phase B planning tests (Batch 7, Task A; Section 5.2 + Section 6 Build).

The base-image allowlist check is a REAL enforced Planner check (not
documentation): a container_build stage whose declared Dockerfile base image
is not in build_policy.allowed_base_images — or undeclared entirely — makes
plan construction raise UnapprovedToolError before anything compiles.
"""

from __future__ import annotations

import pytest

from ci_agent.core.models.common import EventType
from ci_agent.core.models.pipeline_spec import PipelineSpec
from ci_agent.core.models.policy_spec import PolicySpec
from ci_agent.planner.planner import Planner, UnapprovedToolError
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.resolver.project_profile import ProjectProfile

PHASE_B_TOOLS = {
    "git": "2.43",
    "ruff": "0.6.0",
    "bandit": "1.7.9",
    "pytest": "8.2.0",
    "gitleaks": "8.18.2",
    "pip-audit": "2.7.2",
    "build": "1.2.1",
    "docker": "27.3.1",
    "syft": "1.18.1",
    "trivy": "0.58.0",
    "cosign": "2.4.1",
}

PHASE_B_IMAGES = [
    "python:3.11-slim",
    "docker:27.3.1-cli",
    "anchore/syft:v1.18.1",
    "aquasec/trivy:0.58.0",
    "sigstore/cosign:v2.4.1",
]


def _policy_spec(allowed_base_images: list[str]) -> PolicySpec:
    return PolicySpec(
        policy_version="1.0.0",
        identity_policy={
            "allowed_repositories": ["example-org/*"],
            "allowed_branches": ["main"],
            "allowed_identities": [],
        },
        tool_policy={
            "approved_tool_versions": dict(PHASE_B_TOOLS),
            "approved_images": list(PHASE_B_IMAGES),
            "forbidden_tools": [],
        },
        security_policy={
            "severity_thresholds": {"critical": 0, "high": 0, "medium": 5, "low": 20},
            "require_secret_scan": True,
            "require_sca": True,
        },
        build_policy={
            "allowed_base_images": allowed_base_images,
            "allowed_egress_domains": ["pypi.org"],
            "max_timeout_seconds": 3600,
        },
        artifact_policy={
            "require_sbom": True,
            "sbom_format": "spdx",
            "require_signing": True,
            "registry_allowlist": ["ghcr.io"],
        },
        approval_policy={
            "require_human_approval_for": ["high", "regulated"],
            "approver_groups": ["security-leads"],
        },
        ai_policy={
            "allowed_model_providers": [],
            "allowed_data_classification": [],
            "require_human_override": True,
        },
    )


def _phase_b_spec(base_image: str | None) -> PipelineSpec:
    stages: list[dict] = [
        {"id": "checkout", "name": "Checkout", "depends_on": []},
        {"id": "format_lint", "name": "Lint", "depends_on": ["checkout"]},
        {"id": "sast", "name": "SAST", "depends_on": ["format_lint"]},
        {"id": "unit_tests", "name": "Unit tests", "depends_on": ["format_lint"]},
        {"id": "secret_scan", "name": "Secret scan", "depends_on": ["sast"]},
        {"id": "dependency_scan", "name": "SCA", "depends_on": ["sast"]},
        {
            "id": "policy_gate",
            "name": "Policy gate",
            "depends_on": ["unit_tests", "secret_scan", "dependency_scan"],
        },
        {"id": "human_approval", "name": "Approval", "depends_on": ["policy_gate"]},
        {"id": "merge_decision", "name": "Merge decision", "depends_on": ["human_approval"]},
        {"id": "full_build", "name": "Full build", "depends_on": ["merge_decision"]},
        {"id": "integration_tests", "name": "Integration tests", "depends_on": ["full_build"]},
        {"id": "coverage_gate", "name": "Coverage gate", "depends_on": ["integration_tests"]},
    ]
    container = {
        "id": "container_build",
        "name": "Container build",
        "depends_on": ["coverage_gate"],
    }
    if base_image is not None:
        container["base_image"] = base_image
    stages.append(container)
    stages += [
        {"id": "sbom_generate", "name": "SBOM", "depends_on": ["container_build"]},
        {"id": "image_scan", "name": "Image scan", "depends_on": ["sbom_generate"]},
        {"id": "sign_attest", "name": "Sign & attest", "depends_on": ["image_scan"]},
        {"id": "publish", "name": "Publish", "depends_on": ["sign_attest"]},
        {"id": "record_evidence", "name": "Record evidence", "depends_on": ["publish"]},
    ]
    return PipelineSpec(
        project_id="example-org/payments-api",
        project_name="Payments API",
        stack={"language": "python"},
        repository={
            "provider": "github",
            "url": "https://github.com/example-org/payments-api",
            "repo_id": "example-org/payments-api",
        },
        trigger={"event_type": EventType.PULL_REQUEST, "branch": "main"},
        stages=stages,
        thresholds={"coverage_percent": 80},
        approvals_required=False,
        artifact_destinations=["ghcr.io/example-org/payments-api"],
        policy_version="1.0.0",
    )


def _profile() -> ProjectProfile:
    """A Python-stack profile matching the conftest canonical fixture."""
    return ProjectProfile(
        project_id="example-org/payments-api",
        business_criticality="high",
        data_sensitivity="confidential",
        risk_tier="high",
        repo_structure="single_repo",
        language_stack="python",
        runner="linux",
        security_tools=["bandit", "pip-audit", "gitleaks"],
        secret_storage="hashicorp_vault",
        coverage_requirement=80.0,
        artifact_repository="github_packages",
        testing_strategy="unit+integration",
        execution_location="github_hosted",
        policy_version_pinned="1.0.0",
        raw_intake_answers={"primary_language": "python"},
    )


@pytest.fixture()
def profile() -> ProjectProfile:
    return _profile()


def test_phase_b_plan_builds_with_allowlisted_base_image(profile: ProjectProfile) -> None:
    planner = Planner(TemplateRegistry(), _policy_spec(list(PHASE_B_IMAGES)))
    plan = planner.build_execution_plan(
        profile, _phase_b_spec("python:3.11-slim"), "1.0.0", run_id="run-b7"
    )
    stage_ids = [step.stage_id for step in plan.resolved_steps]
    assert stage_ids[-1] == "record_evidence"
    # Phase B jobs follow the Phase A terminal gate in plan order.
    assert stage_ids.index("full_build") > stage_ids.index("merge_decision")


def test_disallowed_base_image_blocks_planning(profile: ProjectProfile) -> None:
    """A non-allowlisted Dockerfile base is a HARD planning failure."""
    planner = Planner(TemplateRegistry(), _policy_spec(list(PHASE_B_IMAGES)))
    with pytest.raises(UnapprovedToolError, match="evil/image:latest"):
        planner.build_execution_plan(
            profile, _phase_b_spec("evil/image:latest"), "1.0.0", run_id="run-b7"
        )


def test_undeclared_base_image_blocks_planning(profile: ProjectProfile) -> None:
    """Missing declaration fails closed too — policy never sees the base."""
    planner = Planner(TemplateRegistry(), _policy_spec(list(PHASE_B_IMAGES)))
    with pytest.raises(UnapprovedToolError, match="no declared base_image"):
        planner.build_execution_plan(profile, _phase_b_spec(None), "1.0.0", run_id="run-b7")


def test_unapproved_phase_b_tool_blocks_planning(profile: ProjectProfile) -> None:
    spec_policy = _policy_spec(list(PHASE_B_IMAGES))
    spec_policy = spec_policy.model_copy(
        update={
            "tool_policy": spec_policy.tool_policy.model_copy(
                update={
                    "approved_tool_versions": {
                        k: v
                        for k, v in spec_policy.tool_policy.approved_tool_versions.items()
                        if k != "trivy"
                    }
                }
            )
        }
    )
    planner = Planner(TemplateRegistry(), spec_policy)
    with pytest.raises(UnapprovedToolError, match=r"trivy@0\.58\.0"):
        planner.build_execution_plan(
            profile, _phase_b_spec("python:3.11-slim"), "1.0.0", run_id="run-b7"
        )
