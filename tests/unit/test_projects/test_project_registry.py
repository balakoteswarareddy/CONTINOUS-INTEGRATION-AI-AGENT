"""Project registry + admin API tests (Batch 5, Task A)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.db.base import Base, create_engine
from ci_agent.governance import load_intake_schema
from ci_agent.ingress.app import create_app
from ci_agent.projects.project_registry import (
    MissingPipelineSpecError,
    ProjectNotRegisteredError,
    ProjectRegistry,
)

INTAKE_SCHEMA = load_intake_schema()


def _answers(
    repository_url: str = "https://github.com/example-org/payments-api",
) -> dict[str, Any]:
    """Canonical complete intake answers (tests/conftest.py)."""
    from tests.conftest import complete_intake_answers

    return dict(complete_intake_answers())


def _spec_document() -> dict[str, Any]:
    from ci_agent.core.models.common import EventType
    from ci_agent.core.models.pipeline_spec import PipelineSpec

    spec = PipelineSpec(
        project_id="example-org/payments-api",
        project_name="Payments API",
        stack={"language": "python", "framework": "fastapi", "version": "3.11"},
        repository={
            "provider": "github",
            "url": "https://github.com/example-org/payments-api",
            "repo_id": "example-org/payments-api",
        },
        trigger={
            "event_type": EventType.PULL_REQUEST,
            "branch": "main",
            "source_sha": "abc123",
        },
        stages=[
            {"id": "checkout", "name": "Checkout", "depends_on": []},
            {"id": "format_lint", "name": "Format & Lint", "depends_on": ["checkout"]},
            {"id": "sast", "name": "SAST", "depends_on": ["format_lint"]},
            {"id": "unit_tests", "name": "Unit Tests", "depends_on": ["format_lint"]},
            {"id": "secret_scan", "name": "Secret Scan", "depends_on": ["sast"]},
            {
                "id": "dependency_scan",
                "name": "Dependency Scan",
                "depends_on": ["sast"],
            },
            {
                "id": "policy_gate",
                "name": "Policy Gate",
                "depends_on": ["unit_tests", "secret_scan", "dependency_scan"],
            },
            {
                "id": "human_approval",
                "name": "Human Approval",
                "depends_on": ["policy_gate"],
            },
            {
                "id": "merge_decision",
                "name": "Merge Decision",
                "depends_on": ["human_approval"],
            },
        ],
        thresholds={"coverage_percent": 80},
        approvals_required=False,
        artifact_destinations=["ghcr://example-org/payments-api"],
        policy_version="1.0.0",
    )
    import json

    return json.loads(spec.model_dump_json())


@pytest.fixture()
def registry(session_factory) -> ProjectRegistry:
    return ProjectRegistry(session_factory)


def test_register_and_get_profile_roundtrip(registry: ProjectRegistry) -> None:
    record = registry.register_project(
        intake_answers=_answers(),
        intake_schema=INTAKE_SCHEMA,
        repository="example-org/payments-api",
    )
    assert record.project_id == "example-org/payments-api"
    assert record.risk_tier == "high"
    profile = registry.get_profile("example-org/payments-api")
    assert profile.risk_tier.value == "high"
    assert profile.language_stack == "python"


def test_unregistered_project_fails_closed(registry: ProjectRegistry) -> None:
    with pytest.raises(ProjectNotRegisteredError):
        registry.get_profile("ghost/repo")


def test_pipeline_spec_content_addressed(registry: ProjectRegistry) -> None:
    registry.register_project(
        intake_answers=_answers(),
        intake_schema=INTAKE_SCHEMA,
        repository="example-org/payments-api",
    )
    first = registry.register_pipeline_spec("example-org/payments-api", _spec_document())
    second = registry.register_pipeline_spec("example-org/payments-api", _spec_document())
    # Same content -> same hash (idempotent versioning).
    assert first.content_hash == second.content_hash
    document = registry.get_pipeline_spec("example-org/payments-api")
    assert document["project_id"] == "example-org/payments-api"
    # Hash-pinned read.
    pinned = registry.get_pipeline_spec("example-org/payments-api", content_hash=first.content_hash)
    assert pinned == document


def test_pipeline_spec_requires_registered_project(registry: ProjectRegistry) -> None:
    with pytest.raises(ProjectNotRegisteredError):
        registry.register_pipeline_spec("ghost/repo", _spec_document())


def test_missing_pipeline_spec_raises(registry: ProjectRegistry) -> None:
    registry.register_project(
        intake_answers=_answers(),
        intake_schema=INTAKE_SCHEMA,
        repository="example-org/payments-api",
    )
    with pytest.raises(MissingPipelineSpecError):
        registry.get_pipeline_spec("example-org/payments-api")


# --------------------------------------------------------------- admin API ---


def _admin_client(tmp_path) -> TestClient:
    engine = create_engine(f"sqlite:///{tmp_path / 'admin.db'}")
    Base.metadata.create_all(engine)
    settings = Settings(env="local", database_url=f"sqlite:///{tmp_path / 'admin.db'}")
    application = create_app(settings)
    return TestClient(application)


def test_admin_register_project_roundtrip(tmp_path) -> None:
    client = _admin_client(tmp_path)
    with client:
        response = client.post(
            "/admin/projects",
            json={"repository": "example-org/payments-api", "intake_answers": _answers()},
            headers={"X-Admin-Key": "ci-agent-local-admin-key"},
        )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["project_id"] == "example-org/payments-api"
    assert body["risk_tier"] == "high"


def test_admin_register_pipeline_spec(tmp_path) -> None:
    client = _admin_client(tmp_path)
    headers = {"X-Admin-Key": "ci-agent-local-admin-key"}
    with client:
        created = client.post(
            "/admin/projects",
            json={"repository": "example-org/payments-api", "intake_answers": _answers()},
            headers=headers,
        )
        assert created.status_code == 201
        spec_response = client.post(
            "/admin/projects/example-org/payments-api/pipeline-spec",
            json={"spec": _spec_document()},
            headers=headers,
        )
    assert spec_response.status_code == 201, spec_response.text
    assert len(spec_response.json()["content_hash"]) == 64


def test_admin_requires_key(tmp_path) -> None:
    client = _admin_client(tmp_path)
    with client:
        missing = client.post(
            "/admin/projects",
            json={"repository": "example-org/payments-api", "intake_answers": _answers()},
        )
        wrong = client.post(
            "/admin/projects",
            json={"repository": "example-org/payments-api", "intake_answers": _answers()},
            headers={"X-Admin-Key": "not-the-key"},
        )
    assert missing.status_code == 401
    assert wrong.status_code == 403


def test_admin_rejects_unknown_project_spec(tmp_path) -> None:
    client = _admin_client(tmp_path)
    with client:
        response = client.post(
            "/admin/projects/ghost-repo/pipeline-spec",
            json={"spec": _spec_document()},
            headers={"X-Admin-Key": "ci-agent-local-admin-key"},
        )
    assert response.status_code == 404
