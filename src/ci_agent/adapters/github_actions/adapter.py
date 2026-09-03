"""GitHub Actions runner adapter (Batch 4, Task A; Report Sections 4.2 and 12).

Implements the generic :class:`RunnerAdapter` seam for GitHub Actions:

- ``compile``     -> workflow YAML (compiler.py) wrapped in a CompiledArtifact.
- ``dispatch``    -> dedicated branch ``ci-agent/<run_id>`` from the source
  revision, commit the workflow file, trigger ``workflow_dispatch`` (explicit
  control — rationale in NOTES.md), then resolve the runner-native run id with
  a bounded retry loop (dispatch calls do not return a run id synchronously).
- ``poll_status`` -> workflow run + check runs mapped into our StageStatus
  vocabulary via explicit, reviewable mapping tables.
- ``fetch_step_logs`` -> raw log text (structured parsing is the Observer's job).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ci_agent.adapters.base import (
    CompiledArtifact,
    DispatchRef,
    RunnerAdapter,
    RunnerStatusSnapshot,
    StageStatusView,
)
from ci_agent.adapters.github_actions.client import GitHubAPIError, GitHubClient
from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.github_actions.compiler import (
    RESULTS_ARTIFACT_NAME,
    WORKFLOW_FILE_NAME,
    compile_to_github_actions,
    stage_id_from_job_id,
)
from ci_agent.core.models.common import StageStatus
from ci_agent.core.models.execution_plan import ExecutionPlan

WORKFLOW_PATH = ".github/workflows/" + WORKFLOW_FILE_NAME
BRANCH_PREFIX = "ci-agent/"

# Run-id resolution after workflow_dispatch (bounded retry, batch spec: max 5
# attempts with backoff).
RUN_ID_RESOLUTION_ATTEMPTS = 5
RUN_ID_RESOLUTION_BACKOFF_SECONDS = 1.0

# --- Explicit, reviewable status-vocabulary mapping tables (batch DoD). ----
# GitHub workflow_run.status -> StageStatus
GITHUB_WORKFLOW_STATUS_TO_STAGE_STATUS: dict[str, StageStatus] = {
    "queued": StageStatus.QUEUED,
    "pending": StageStatus.PENDING,
    "in_progress": StageStatus.RUNNING,
    "completed": StageStatus.PASSED,  # refined by conclusion below
    "requested": StageStatus.QUEUED,
    "waiting": StageStatus.QUEUED,
}

# GitHub conclusion (workflow_run/check_run) -> StageStatus
GITHUB_CONCLUSION_TO_STAGE_STATUS: dict[str, StageStatus] = {
    "success": StageStatus.PASSED,
    "failure": StageStatus.FAILED,
    "cancelled": StageStatus.CANCELLED,
    "timed_out": StageStatus.FAILED,
    "skipped": StageStatus.SKIPPED,
    "neutral": StageStatus.PASSED,
    "startup_failure": StageStatus.FAILED,
    "stale": StageStatus.CANCELLED,
}

# GitHub check_run.status -> StageStatus
GITHUB_CHECK_RUN_STATUS_TO_STAGE_STATUS: dict[str, StageStatus] = {
    "queued": StageStatus.QUEUED,
    "pending": StageStatus.PENDING,
    "in_progress": StageStatus.RUNNING,
    "completed": StageStatus.PASSED,  # refined by conclusion
    "idle": StageStatus.PENDING,
}


def map_workflow_run_status(status: str, conclusion: str | None) -> StageStatus:
    """Map a GitHub workflow_run (status, conclusion) to StageStatus.

    Explicit table lookups only; unknown values map to FAILED — fail-closed
    (an unknown state must never look like success).
    """
    if status == "completed" and conclusion:
        return GITHUB_CONCLUSION_TO_STAGE_STATUS.get(conclusion, StageStatus.FAILED)
    return GITHUB_WORKFLOW_STATUS_TO_STAGE_STATUS.get(status, StageStatus.FAILED)


def map_check_run(status: str, conclusion: str | None) -> StageStatus:
    """Map a GitHub check_run (status, conclusion) to StageStatus."""
    if status == "completed" and conclusion:
        return GITHUB_CONCLUSION_TO_STAGE_STATUS.get(conclusion, StageStatus.FAILED)
    return GITHUB_CHECK_RUN_STATUS_TO_STAGE_STATUS.get(status, StageStatus.FAILED)


class GitHubActionsAdapter(RunnerAdapter):
    """Adapter #1: GitHub Actions (Report Section 12 — adapters, not vendor logic)."""

    def __init__(
        self,
        client: GitHubClient,
        registry: CommandTemplateRegistry | None = None,
        run_id_resolution_attempts: int = RUN_ID_RESOLUTION_ATTEMPTS,
        run_id_resolution_backoff_seconds: float = RUN_ID_RESOLUTION_BACKOFF_SECONDS,
    ) -> None:
        self._client = client
        self._registry = registry or CommandTemplateRegistry()
        self._attempts = run_id_resolution_attempts
        self._backoff = run_id_resolution_backoff_seconds

    # ------------------------------------------------------------------ compile

    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
        """Compile the plan into workflow YAML.

        Requires generic metadata keys ``repository`` and ``source_sha`` (the
        dispatch coordinates an ExecutionPlan intentionally does not carry).
        """
        metadata = metadata or {}
        missing = [key for key in ("repository", "source_sha") if not metadata.get(key)]
        if missing:
            raise ValueError(f"compile metadata is missing required keys: {missing}")
        yaml_text = compile_to_github_actions(plan, self._registry)
        digest = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
        return CompiledArtifact(
            kind="github_actions_workflow",
            content=yaml_text,
            content_hash=f"sha256:{digest}",
            metadata={**metadata, "workflow_path": WORKFLOW_PATH},
        )

    # ----------------------------------------------------------------- dispatch

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        """Create the ci-agent branch, commit the workflow, trigger dispatch."""
        repository = artifact.metadata["repository"]
        source_sha = artifact.metadata["source_sha"]
        workflow_path = artifact.metadata.get("workflow_path", WORKFLOW_PATH)
        branch = f"{BRANCH_PREFIX}{run_id}"

        self._client.create_branch(repository, branch, source_sha)
        self._client.create_or_update_file(
            repository,
            workflow_path,
            artifact.content,
            branch,
            message=f"ci-agent: workflow for run {run_id}",
        )
        self._client.trigger_workflow_dispatch(repository, WORKFLOW_FILE_NAME, branch)

        external_run_id = self._resolve_run_id(repository, branch)
        return DispatchRef(
            run_id=run_id,
            repository=repository,
            branch=branch,
            external_run_id=external_run_id,
            workflow_ref=workflow_path,
        )

    def _resolve_run_id(self, repository: str, branch: str) -> str | None:
        """Bounded retry loop resolving the workflow run id after dispatch."""
        for attempt in range(self._attempts):
            if attempt:
                time.sleep(self._backoff * attempt)
            runs = self._client.list_workflow_runs_for_branch(repository, branch)
            for run in runs:
                if run.get("head_branch") == branch:
                    return str(run.get("id"))
        return None

    # -------------------------------------------------------------- poll_status

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        """Fetch workflow run + check runs, mapped into our vocabulary."""
        repository = dispatch_ref.repository
        external_run_id = dispatch_ref.external_run_id
        if not external_run_id:
            raise ValueError(
                f"dispatch_ref for run {dispatch_ref.run_id} has no external_run_id yet"
            )

        run = self._client.get_workflow_run(repository, external_run_id)
        status = map_workflow_run_status(str(run.get("status", "")), run.get("conclusion"))
        completed = str(run.get("status", "")) == "completed"

        stages: list[StageStatusView] = []
        for check_run in self._client.get_check_runs(repository, dispatch_ref.branch):
            name = str(check_run.get("name", ""))
            if name == "ci-agent-results":
                continue  # the summary job, not a stage
            conclusion = check_run.get("conclusion")
            mapped = map_check_run(str(check_run.get("status", "")), conclusion)
            stages.append(
                StageStatusView(
                    stage_id=_stage_id_from_check_run_name(name),
                    status=mapped,
                    raw_status=str(check_run.get("status", "")),
                    raw_conclusion=check_run.get("conclusion"),
                )
            )

        return RunnerStatusSnapshot(
            run_id=dispatch_ref.run_id,
            dispatch_ref=dispatch_ref,
            status=status,
            completed=completed,
            stages=stages,
            raw={"workflow_run": run},
        )

    # ------------------------------------------------------------ step logs

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        """Download the run's log archive and return the requested job section.

        MVP: returns raw text; the Execution Observer owns structured parsing
        (Report Section 10). Raises GitHubAPIError on any HTTP failure.
        """
        if not dispatch_ref.external_run_id:
            raise GitHubAPIError(
                f"cannot fetch logs for run {dispatch_ref.run_id}: "
                "external run id not resolved yet"
            )
        response = self._client.request(
            "GET",
            f"/repos/{dispatch_ref.repository}/actions/runs/{dispatch_ref.external_run_id}/logs",
        )
        # GitHub returns a redirect to a zip; httpx follows it. The archive
        # layout is per-job files — for MVP, return the raw bytes decoded if
        # plain text, else the zip member matching step_id.
        content_type = response.headers.get("content-type", "")
        if "zip" in content_type:
            import io
            import zipfile

            archive = zipfile.ZipFile(io.BytesIO(response.content))
            for name in archive.namelist():
                if step_id in name:
                    return archive.read(name).decode("utf-8", errors="replace")
            return ""
        return response.text

    # --------------------------------------------------------------- results

    def download_results_artifact(self, dispatch_ref: DispatchRef) -> dict[str, Any] | None:
        """Download and parse the structured ``ci-agent-results`` artifact.

        Returns the parsed JSON document (per-stage status/exit codes) or
        ``None`` when the artifact does not exist (yet).
        """
        if not dispatch_ref.external_run_id:
            return None
        artifacts = self._client.list_artifacts(
            dispatch_ref.repository, dispatch_ref.external_run_id
        )
        target = next((a for a in artifacts if a.get("name") == RESULTS_ARTIFACT_NAME), None)
        if target is None:
            return None
        blob = self._client.download_artifact(dispatch_ref.repository, str(target["id"]))
        import io
        import json
        import zipfile

        archive = zipfile.ZipFile(io.BytesIO(blob))
        for name in archive.namelist():
            if name.endswith(".json"):
                return dict(json.loads(archive.read(name).decode("utf-8")))
        return None


def _stage_id_from_check_run_name(name: str) -> str:
    """Map a check run name to a stage id.

    Our compiled stage jobs are named exactly ``<stage_id>``; unknown names are
    returned verbatim so the Observer can skip them explicitly.
    """
    if name.startswith("stage-"):
        try:
            return stage_id_from_job_id(name)
        except ValueError:  # pragma: no cover - defensive
            return name
    return name
