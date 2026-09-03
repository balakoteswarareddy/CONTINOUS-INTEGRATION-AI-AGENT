"""Telemetry event models (Batch 8, Task E; Report Section 9).

Pydantic value objects mirroring the OTel CI/CD semantic-convention concepts
(``cicd.pipeline.*`` for pipeline runs, ``cicd.pipeline.task.*`` for stages,
``cicd.worker.*`` for workers). ``attributes`` carries additional OTel-aligned
fields; its keys should come from :mod:`ci_agent.telemetry.conventions`
(internal extensions use the ``ci_agent.`` prefix).

Frozen + ``extra="forbid"`` per the project-wide Batch 1 convention: telemetry
events are immutable value objects and unknown fields are rejected, not
dropped.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ci_agent.core.models.common import StageStatus


class PipelineRunEvent(BaseModel):
    """A pipeline-run lifecycle event (OTel ``cicd.pipeline.*`` concept)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str
    pipeline_name: str
    run_id: str
    runner: str
    status: StageStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class StageEvent(BaseModel):
    """A stage (task) lifecycle event (OTel ``cicd.pipeline.task.*``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    stage_id: str
    task_type: str
    status: StageStatus
    duration_ms: int | None = None
    exit_code: int | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class WorkerEvent(BaseModel):
    """A runner-worker state event (OTel ``cicd.worker.*`` concept)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    worker_id: str
    worker_state: str
    runner: str
    attributes: dict[str, str] = Field(default_factory=dict)


__all__ = [
    "PipelineRunEvent",
    "StageEvent",
    "WorkerEvent",
]
