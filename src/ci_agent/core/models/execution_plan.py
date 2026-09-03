"""ExecutionPlan — the compiled, runner-agnostic execution contract.

Report Section 4.1, bullet 3: the plan a Planner produces by resolving a
PipelineSpec against PolicySpec. It contains resolved steps, pinned tool
versions, container images and scoped identity references — never raw
credentials (Report Section 7 trust boundaries).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RetryPolicy(BaseModel):
    """Retry behaviour for a resolved step (Report Section 4.1, bullet 3)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_retries: int = Field(default=0, ge=0)
    retryable: bool = False


class ResolvedStep(BaseModel):
    """A single fully-resolved execution step (Report Section 4.1, bullet 3)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str
    stage_id: str
    tool_name: str
    tool_version: str
    container_image: str | None = None
    command_template_id: str
    timeout_seconds: int = Field(gt=0)
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    resource_limits: dict[str, str] = Field(default_factory=dict)
    expected_outputs: list[str] = Field(default_factory=list)


class ExecutionPlan(BaseModel):
    """A compiled plan ready to be handed to a runner adapter (Report Section 4.1, bullet 3)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    # id/hash of the PipelineSpec this plan was compiled from (traceability).
    pipeline_spec_ref: str
    resolved_steps: list[ResolvedStep]
    # Scoped identity references — NOT actual credentials (Report Section 7).
    identities: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _validate_step_ids_unique(self) -> Self:
        """Step ids must be unique within a plan so evidence can reference them unambiguously."""
        step_ids = [step.step_id for step in self.resolved_steps]
        duplicates = sorted({sid for sid in step_ids if step_ids.count(sid) > 1})
        if duplicates:
            raise ValueError(
                f"step_id values must be unique within an ExecutionPlan; duplicated: {duplicates}"
            )
        return self
