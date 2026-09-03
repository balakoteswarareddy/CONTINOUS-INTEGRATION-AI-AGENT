"""Runner Adapter Layer — the vendor-neutrality seam (Batch 4, Stage 9; Report Sections 4.2 and 12).

``RunnerAdapter`` is the abstract interface every runner adapter (GitHub
Actions today; GitLab/Jenkins/others later) must implement. Per Section 12
("adapters, not provider-specific logic") no GitHub-specific type, field or
vocabulary leaks into this module: ``CompiledArtifact``, ``DispatchRef`` and
``RunnerStatusSnapshot`` are generic Pydantic models whose semantics every
adapter shares.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ci_agent.core.models.common import StageStatus
from ci_agent.core.models.execution_plan import ExecutionPlan


class CompiledArtifact(BaseModel):
    """A pipeline plan compiled into a runner-specific artifact (generic shape).

    For the GitHub Actions adapter the ``content`` is workflow YAML text and
    ``content_hash`` a sha256 of it. ``metadata`` carries adapter-specific
    dispatch coordinates (e.g. target repository, source sha) under GENERIC
    keys so the shared interface stays vendor-neutral.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str  # e.g. "github_actions_workflow"
    content: str
    content_hash: str
    metadata: dict[str, str] = Field(default_factory=dict)


class DispatchRef(BaseModel):
    """Identity of one dispatched execution on a runner (generic shape)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    repository: str
    branch: str
    # Runner-native execution id once known (e.g. a workflow run id); adapters
    # may resolve it asynchronously after dispatch.
    external_run_id: str | None = None
    workflow_ref: str | None = None
    # Batch 8: which adapter produced this dispatch (github_actions |
    # gitlab_ci | jenkins) — the orchestrator persists it on the run so
    # webhooks and reconciliation resolve the right provider. Vendor-neutral:
    # a registry key, never provider-specific types.
    provider: str | None = None
    dispatched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class StageStatusView(BaseModel):
    """Runner-reported status of one stage/step (generic shape)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage_id: str
    status: StageStatus
    exit_code: int | None = None
    raw_status: str | None = None
    raw_conclusion: str | None = None


class RunnerStatusSnapshot(BaseModel):
    """Point-in-time status of a dispatched run, expressed in our vocabulary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    dispatch_ref: DispatchRef
    status: StageStatus
    completed: bool
    stages: list[StageStatusView] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class RunnerAdapter(ABC):
    """Abstract runner adapter interface (Report Section 4.2 / Section 12).

    Batch 4 note: ``compile`` accepts optional generic ``metadata`` (target
    repository, source revision) because an ``ExecutionPlan`` deliberately does
    not carry runner/dispatch coordinates; this is a documented signature
    extension of the batch's sketch (NOTES.md).
    """

    @abstractmethod
    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
        """Compile a validated ExecutionPlan into a runner-specific artifact."""

    @abstractmethod
    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        """Dispatch (start) a compiled artifact on the runner."""

    @abstractmethod
    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        """Fetch the current status of a dispatched run."""

    @abstractmethod
    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        """Fetch logs for one step (raw text; structured parsing is the Observer's job)."""
