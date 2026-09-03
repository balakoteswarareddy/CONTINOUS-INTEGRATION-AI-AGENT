"""EvidenceModel — immutable, hash-linked evidence for a pipeline run.

Report Section 4.1, bullet 4: the record consumed by the Evidence Store and
Report Generator. Captures tool versions, findings, approvals, artifact
digests/references and attestations so every promotion decision is auditable
(Report Section 7 — evidence and trust boundaries).
"""

from __future__ import annotations

from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ci_agent.core.models.common import ApprovalStatus, Severity


class Finding(BaseModel):
    """A single scanner finding attached to a run (Report Section 4.1, bullet 4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Severity
    scanner: str
    rule_id: str
    component: str | None = None
    disposition: str


class ApprovalRecord(BaseModel):
    """A human approval decision recorded as evidence (Report Section 4.1, bullet 4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approver: str
    status: ApprovalStatus
    timestamp: datetime


class ArtifactRef(BaseModel):
    """Content-addressed reference to a produced artifact (Report Section 4.1, bullet 4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    digest: str
    registry: str
    sbom_ref: str | None = None
    signature_ref: str | None = None


class EvidenceModel(BaseModel):
    """The complete evidence bundle for one pipeline run (Report Section 4.1, bullet 4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    source_commit: str
    pipeline_hash: str
    tool_versions: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    approvals: list[ApprovalRecord] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    attestations: list[str] = Field(default_factory=list)
    # Named event timestamps, e.g. "started_at", "completed_at".
    timestamps: dict[str, datetime] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_timestamp_ordering(self) -> Self:
        """If both lifecycle timestamps are present, the run must not complete before it starts."""
        started = self.timestamps.get("started_at")
        completed = self.timestamps.get("completed_at")
        if started is not None and completed is not None and completed < started:
            raise ValueError("timestamps['completed_at'] must not precede timestamps['started_at']")
        return self
