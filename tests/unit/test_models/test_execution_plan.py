"""Unit tests for ExecutionPlan (Batch 1, Task B — Report Section 4.1, bullet 3)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy


def resolved_step_payload(step_id: str = "step-build", stage_id: str = "build") -> dict:
    """A fully valid ResolvedStep payload."""
    return {
        "step_id": step_id,
        "stage_id": stage_id,
        "tool_name": "python",
        "tool_version": "3.11.8",
        "container_image": "python:3.11-slim",
        "command_template_id": "tmpl-python-build",
        "timeout_seconds": 1800,
        "retry_policy": {"max_retries": 2, "retryable": True},
        "resource_limits": {"cpu": "2", "memory": "4Gi"},
        "expected_outputs": ["dist/*.whl"],
    }


def execution_plan_payload() -> dict:
    """A fully valid ExecutionPlan payload (created_at intentionally omitted -> defaults)."""
    return {
        "run_id": "run-2026-09-03-0001",
        "pipeline_spec_ref": "sha256:1a2b3c4d5e6f",
        "resolved_steps": [
            resolved_step_payload("step-build", "build"),
            resolved_step_payload("step-test", "test"),
        ],
        "identities": ["urn:ci:identity:acme-builder"],
    }


class TestValidConstruction:
    def test_valid_payload_constructs(self) -> None:
        plan = ExecutionPlan(**execution_plan_payload())

        assert plan.run_id == "run-2026-09-03-0001"
        assert plan.pipeline_spec_ref == "sha256:1a2b3c4d5e6f"
        assert [step.step_id for step in plan.resolved_steps] == ["step-build", "step-test"]
        assert plan.resolved_steps[0].retry_policy == RetryPolicy(max_retries=2, retryable=True)
        assert plan.identities == ["urn:ci:identity:acme-builder"]

    def test_created_at_defaults_to_tz_aware_utc_now(self) -> None:
        before = datetime.now(UTC)
        plan = ExecutionPlan(**execution_plan_payload())
        after = datetime.now(UTC)

        assert plan.created_at.tzinfo is not None
        assert before <= plan.created_at <= after

    def test_explicit_created_at_is_preserved(self) -> None:
        payload = execution_plan_payload()
        payload["created_at"] = "2026-09-03T10:00:00+00:00"

        plan = ExecutionPlan(**payload)
        assert plan.created_at == datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

    def test_step_defaults(self) -> None:
        step = ResolvedStep(
            step_id="s1",
            stage_id="build",
            tool_name="python",
            tool_version="3.11.8",
            command_template_id="tmpl",
            timeout_seconds=60,
        )
        assert step.container_image is None
        assert step.retry_policy == RetryPolicy(max_retries=0, retryable=False)
        assert step.resource_limits == {}
        assert step.expected_outputs == []


class TestRequiredFields:
    @pytest.mark.parametrize("field_to_remove", ["run_id", "pipeline_spec_ref", "resolved_steps"])
    def test_missing_required_field_raises(self, field_to_remove: str) -> None:
        payload = execution_plan_payload()
        del payload[field_to_remove]

        with pytest.raises(ValidationError) as excinfo:
            ExecutionPlan(**payload)
        assert field_to_remove in str(excinfo.value)

    def test_missing_nested_required_field_raises(self) -> None:
        payload = execution_plan_payload()
        del payload["resolved_steps"][0]["command_template_id"]

        with pytest.raises(ValidationError) as excinfo:
            ExecutionPlan(**payload)
        assert "command_template_id" in str(excinfo.value)


class TestValidators:
    def test_unique_step_ids_pass(self) -> None:
        plan = ExecutionPlan(**execution_plan_payload())
        assert len({step.step_id for step in plan.resolved_steps}) == 2

    def test_duplicate_step_ids_rejected(self) -> None:
        payload = execution_plan_payload()
        payload["resolved_steps"][1] = resolved_step_payload("step-build", "test")

        with pytest.raises(ValidationError, match="step_id values must be unique"):
            ExecutionPlan(**payload)

    def test_zero_timeout_rejected(self) -> None:
        payload = execution_plan_payload()
        payload["resolved_steps"][0]["timeout_seconds"] = 0

        with pytest.raises(ValidationError):
            ExecutionPlan(**payload)

    def test_negative_retry_count_rejected(self) -> None:
        payload = execution_plan_payload()
        payload["resolved_steps"][0]["retry_policy"] = {"max_retries": -1, "retryable": True}

        with pytest.raises(ValidationError):
            ExecutionPlan(**payload)


class TestSerialization:
    def test_model_dump_json_round_trip(self) -> None:
        plan = ExecutionPlan(**execution_plan_payload())

        dumped = json.loads(plan.model_dump_json())

        assert dumped["resolved_steps"][0]["retry_policy"] == {"max_retries": 2, "retryable": True}
        # Pydantic v2 serializes tz-aware UTC datetimes with a trailing "Z".
        assert dumped["created_at"].endswith("Z")
        reparsed = ExecutionPlan(**dumped)
        assert reparsed == plan

    def test_extra_fields_rejected(self) -> None:
        payload = execution_plan_payload()
        payload["credentials"] = "should-never-be-here"

        with pytest.raises(ValidationError, match="credentials"):
            ExecutionPlan(**payload)
