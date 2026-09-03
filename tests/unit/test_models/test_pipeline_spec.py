"""Unit tests for PipelineSpec (Batch 1, Task B — Report Section 4.1, bullet 1)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ci_agent.core.models.pipeline_spec import EventType, PipelineSpec, StageDefinition


def pipeline_spec_payload() -> dict:
    """A fully valid PipelineSpec payload used as the base for tests."""
    return {
        "project_id": "payments-api",
        "project_name": "Payments API",
        "stack": {"language": "python", "framework": "fastapi", "version": "3.11"},
        "repository": {
            "provider": "github",
            "url": "https://github.com/acme/payments-api",
            "repo_id": "acme/payments-api",
        },
        "trigger": {
            "event_type": "pull_request",
            "branch": "feature/checkout",
            "source_sha": "abc123",
        },
        "stages": [
            {"id": "build", "name": "Build", "depends_on": [], "required_tools": ["python"]},
            {"id": "test", "name": "Test", "depends_on": ["build"], "required_tools": ["pytest"]},
            {
                "id": "scan",
                "name": "Security Scan",
                "depends_on": ["build"],
                "required_tools": ["trivy"],
            },
        ],
        "thresholds": {"coverage_percent": 80, "max_critical_findings": 0},
        "approvals_required": False,
        "artifact_destinations": ["ghcr://acme/payments-api"],
        "policy_version": "1.0.0",
    }


class TestValidConstruction:
    def test_valid_payload_constructs(self) -> None:
        spec = PipelineSpec(**pipeline_spec_payload())

        assert spec.project_id == "payments-api"
        assert spec.stack.language == "python"
        assert spec.stack.framework == "fastapi"
        assert spec.repository.provider == "github"
        assert spec.trigger.event_type is EventType.PULL_REQUEST
        assert [stage.id for stage in spec.stages] == ["build", "test", "scan"]
        assert spec.thresholds["coverage_percent"] == 80
        assert spec.approvals_required is False
        assert spec.policy_version == "1.0.0"

    def test_optional_nested_fields_default_to_none(self) -> None:
        payload = pipeline_spec_payload()
        payload["trigger"] = {"event_type": "push"}
        spec = PipelineSpec(**payload)

        assert spec.trigger.branch is None
        assert spec.trigger.source_sha is None

    def test_stage_defaults(self) -> None:
        stage = StageDefinition(id="deploy", name="Deploy")
        assert stage.depends_on == []
        assert stage.required_tools == []


class TestRequiredFields:
    @pytest.mark.parametrize(
        "field_to_remove",
        [
            "project_id",
            "project_name",
            "stack",
            "repository",
            "trigger",
            "stages",
            "approvals_required",
            "policy_version",
        ],
    )
    def test_missing_required_field_raises(self, field_to_remove: str) -> None:
        payload = pipeline_spec_payload()
        del payload[field_to_remove]

        with pytest.raises(ValidationError) as excinfo:
            PipelineSpec(**payload)
        assert field_to_remove in str(excinfo.value)

    def test_missing_nested_required_field_raises(self) -> None:
        payload = pipeline_spec_payload()
        del payload["trigger"]["event_type"]

        with pytest.raises(ValidationError) as excinfo:
            PipelineSpec(**payload)
        assert "event_type" in str(excinfo.value)


class TestStageGraphValidator:
    def test_valid_dependency_chain_passes(self) -> None:
        spec = PipelineSpec(**pipeline_spec_payload())
        assert spec.stages[1].depends_on == ["build"]

    def test_empty_stages_rejected(self) -> None:
        payload = pipeline_spec_payload()
        payload["stages"] = []

        with pytest.raises(ValidationError, match="stages must not be empty"):
            PipelineSpec(**payload)

    def test_unknown_dependency_rejected(self) -> None:
        payload = pipeline_spec_payload()
        payload["stages"][1]["depends_on"] = ["does-not-exist"]

        with pytest.raises(ValidationError, match="depends_on references unknown stage ids"):
            PipelineSpec(**payload)

    def test_duplicate_stage_ids_rejected(self) -> None:
        payload = pipeline_spec_payload()
        payload["stages"].append(dict(payload["stages"][0]))

        with pytest.raises(ValidationError, match="duplicated stage ids"):
            PipelineSpec(**payload)

    def test_self_dependency_rejected_as_cycle(self) -> None:
        payload = pipeline_spec_payload()
        payload["stages"][0]["depends_on"] = ["build"]

        with pytest.raises(ValidationError, match="dependency cycle"):
            PipelineSpec(**payload)

    def test_two_stage_cycle_rejected(self) -> None:
        payload = pipeline_spec_payload()
        payload["stages"][1]["depends_on"] = ["build", "scan"]
        payload["stages"][2]["depends_on"] = ["test"]

        with pytest.raises(ValidationError, match="dependency cycle"):
            PipelineSpec(**payload)


class TestPolicyVersionValidator:
    def test_valid_semver_passes(self) -> None:
        payload = pipeline_spec_payload()
        payload["policy_version"] = "2.1.0-rc.1"
        assert PipelineSpec(**payload).policy_version == "2.1.0-rc.1"

    def test_invalid_semver_rejected(self) -> None:
        payload = pipeline_spec_payload()
        payload["policy_version"] = "1.0"

        with pytest.raises(ValidationError, match="Invalid semantic version"):
            PipelineSpec(**payload)


class TestSerialization:
    def test_model_dump_json_round_trip(self) -> None:
        spec = PipelineSpec(**pipeline_spec_payload())

        dumped = json.loads(spec.model_dump_json())

        assert dumped["trigger"]["event_type"] == "pull_request"
        assert dumped["stages"][1]["depends_on"] == ["build"]
        assert dumped["thresholds"]["max_critical_findings"] == 0
        assert dumped["policy_version"] == "1.0.0"
        # All four canonical models must dump cleanly — no non-serializable types.
        reparsed = PipelineSpec(**dumped)
        assert reparsed == spec

    def test_extra_fields_rejected(self) -> None:
        payload = pipeline_spec_payload()
        payload["unknown_field"] = "nope"

        with pytest.raises(ValidationError, match="unknown_field"):
            PipelineSpec(**payload)
