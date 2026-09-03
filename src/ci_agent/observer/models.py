"""Pydantic views over the StageExecutionRecord ORM rows (Batch 4, Task B).

These views are what reports and (later) APIs consume — ORM rows never leak
out of the persistence layer.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from ci_agent.core.models.common import StageStatus


class StageExecutionView(BaseModel):
    """Read model of one stage execution (Report Section 4.2 — Execution Observer)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    stage_id: str
    status: StageStatus
    exit_code: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    logs_ref: str | None = None
    findings_ref: str | None = None

    @classmethod
    def from_record(cls, record: object) -> StageExecutionView:
        """Build the view from a StageExecutionRecord ORM row."""
        return cls(
            run_id=record.run_id,  # type: ignore[attr-defined]
            stage_id=record.stage_id,  # type: ignore[attr-defined]
            status=StageStatus(record.status),  # type: ignore[attr-defined]
            exit_code=record.exit_code,  # type: ignore[attr-defined]
            started_at=record.started_at,  # type: ignore[attr-defined]
            completed_at=record.completed_at,  # type: ignore[attr-defined]
            duration_ms=record.duration_ms,  # type: ignore[attr-defined]
            logs_ref=record.logs_ref,  # type: ignore[attr-defined]
            findings_ref=record.findings_ref,  # type: ignore[attr-defined]
        )
