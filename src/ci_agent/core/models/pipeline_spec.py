"""PipelineSpec — the vendor-neutral pipeline specification.

Report Section 4.1, bullet 1: "Do not make YAML the internal source of truth.
Store a vendor-neutral pipeline specification first, then compile it into
runner-specific YAML or API calls." This model is that stored specification.
"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ci_agent.core.models.common import EventType, validate_semver


class StackInfo(BaseModel):
    """Language/runtime stack of the project (Report Section 14 — language_stack intake section)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    language: str
    framework: str | None = None
    version: str | None = None


class RepositoryRef(BaseModel):
    """Reference to the source repository (provider-neutral; Report Section 4.1, bullet 1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    url: str
    repo_id: str


class TriggerInfo(BaseModel):
    """What triggered this pipeline specification (Report Section 4.1, bullet 1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: EventType
    branch: str | None = None
    source_sha: str | None = None


class StageDefinition(BaseModel):
    """A single stage in the vendor-neutral pipeline (Report Section 4.1, bullet 1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    depends_on: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    # Batch 7 (Section 5.2/6 — Build family): the Dockerfile base image the
    # container_build stage builds FROM, DECLARED in the spec and enforced by
    # the Planner against build_policy.allowed_base_images (hard fail on a
    # non-allowlisted image — a real enforced check, never documentation).
    base_image: str | None = None


class PipelineSpec(BaseModel):
    """Vendor-neutral pipeline specification (Report Section 4.1, bullet 1).

    This is the internal source of truth. Runner-specific YAML or API calls are
    compiled FROM this model — never the other way around.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: str
    project_name: str
    stack: StackInfo
    repository: RepositoryRef
    trigger: TriggerInfo
    stages: list[StageDefinition]
    # Generic threshold bag for the MVP (coverage %, severity max counts, ...).
    # Kept as dict[str, float | int] on purpose; refine into typed fields later.
    thresholds: dict[str, float | int] = Field(default_factory=dict)
    approvals_required: bool
    artifact_destinations: list[str] = Field(default_factory=list)
    # Semantic version of the PolicySpec this pipeline was validated against —
    # cross-links PipelineSpec to PolicySpec (Report Section 4.1).
    policy_version: str

    @field_validator("policy_version")
    @classmethod
    def _policy_version_is_semver(cls, value: str) -> str:
        return validate_semver(value)

    @model_validator(mode="after")
    def _validate_stage_graph(self) -> Self:
        """Enforce stage-graph correctness: non-empty, unique ids, resolvable depends_on."""
        if not self.stages:
            raise ValueError("stages must not be empty: a pipeline needs at least one stage")

        stage_ids = [stage.id for stage in self.stages]
        duplicates = sorted({sid for sid in stage_ids if stage_ids.count(sid) > 1})
        if duplicates:
            raise ValueError(f"stage ids must be unique; duplicated stage ids: {duplicates}")

        known = set(stage_ids)
        unknown = sorted({dep for stage in self.stages for dep in stage.depends_on} - known)
        if unknown:
            raise ValueError(
                f"depends_on references unknown stage ids: {unknown}; "
                f"known stage ids: {sorted(known)}"
            )

        # Kahn's algorithm: a stage graph with a dependency cycle (including a
        # self-dependency) can never be executed, so reject it at construction.
        remaining = {stage.id: list(stage.depends_on) for stage in self.stages}
        resolved: set[str] = set()
        while remaining:
            ready = {sid for sid, deps in remaining.items() if all(dep in resolved for dep in deps)}
            if not ready:
                raise ValueError(
                    f"stages contain a dependency cycle involving: {sorted(remaining)}"
                )
            resolved |= ready
            for sid in ready:
                del remaining[sid]
        return self
