"""Shared pytest fixtures for the CI Agent test suite."""

from __future__ import annotations

import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.pipeline_spec import PipelineSpec
from ci_agent.core.models.policy_spec import PolicySpec
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.resolver.project_profile import ProjectProfile


@pytest.fixture()
def memory_engine() -> Engine:
    """A fresh in-memory SQLite engine with all tables created (fast unit tests)."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def session_factory(memory_engine: Engine) -> sessionmaker:
    return get_session_factory(memory_engine)


@pytest.fixture()
def audit_store(session_factory) -> AuditStore:
    return AuditStore(session_factory)


@pytest.fixture()
def phase_a_pipeline_spec() -> PipelineSpec:
    """A Python Phase A pipeline spec matching the Batch 3 planner template stages."""
    from ci_agent.core.models.common import EventType

    return PipelineSpec(
        project_id="example-org/payments-api",
        project_name="Payments API",
        stack={"language": "python", "framework": "fastapi", "version": "3.11"},
        repository={
            "provider": "github",
            "url": "https://github.com/example-org/payments-api",
            "repo_id": "example-org/payments-api",
        },
        trigger={"event_type": EventType.PULL_REQUEST, "branch": "main", "source_sha": "abc123"},
        stages=[
            {"id": "checkout", "name": "Checkout", "depends_on": []},
            {"id": "format_lint", "name": "Format & Lint", "depends_on": ["checkout"]},
            {"id": "sast", "name": "SAST", "depends_on": ["format_lint"]},
            {"id": "unit_tests", "name": "Unit Tests", "depends_on": ["format_lint"]},
            {"id": "secret_scan", "name": "Secret Scan", "depends_on": ["sast"]},
            {"id": "dependency_scan", "name": "Dependency Scan", "depends_on": ["sast"]},
            {
                "id": "policy_gate",
                "name": "Policy Gate",
                "depends_on": ["unit_tests", "secret_scan", "dependency_scan"],
            },
            {"id": "human_approval", "name": "Human Approval", "depends_on": ["policy_gate"]},
            {"id": "merge_decision", "name": "Merge Decision", "depends_on": ["human_approval"]},
        ],
        thresholds={"coverage_percent": 80},
        approvals_required=True,
        artifact_destinations=["ghcr://example-org/payments-api"],
        policy_version="1.0.0",
    )


@pytest.fixture()
def python_project_profile() -> ProjectProfile:
    """A resolved ProjectProfile for a Python project (high risk tier)."""
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
def approved_policy_spec() -> PolicySpec:
    """A PolicySpec whose approvals match the Batch 3 python template exactly."""
    return PolicySpec(
        policy_version="1.0.0",
        identity_policy={
            "allowed_repositories": ["example-org/*"],
            "allowed_branches": ["main", "release/*", "feature/*"],
            "allowed_identities": [],
        },
        tool_policy={
            "approved_tool_versions": {
                "git": "2.43",
                "ruff": "0.6.0",
                "bandit": "1.7.9",
                "pytest": "8.2.0",
                "gitleaks": "8.18.2",
                "pip-audit": "2.7.2",
            },
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
            "allowed_egress_domains": ["pypi.org", "files.pythonhosted.org"],
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
