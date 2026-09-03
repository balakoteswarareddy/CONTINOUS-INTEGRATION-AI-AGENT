"""GitLab CI runner adapter (Batch 8, Task A; Report Sections 4.2 and 12).

Implements the generic :class:`RunnerAdapter` seam for GitLab CI — the
interface is implemented as written, never extended (conformance-tested):

- ``compile``     -> ``.gitlab-ci.yml`` text (compiler.py) wrapped in a
  CompiledArtifact (kind ``gitlab_ci_pipeline``).
- ``dispatch``    -> create the dedicated branch ``ci-agent/<run_id>`` from
  the source revision, commit the pipeline file via the repository files
  API, trigger the pipeline explicitly on that branch (the compiled
  ``workflow: rules`` restrict execution to API-triggered pipelines), then
  resolve the pipeline id — primarily from the trigger response (GitLab
  returns the created pipeline synchronously), with the GitHub-style bounded
  retry (max 5 attempts, linear backoff) as the fallback when the response
  carries no id.
- ``poll_status`` -> pipeline + jobs mapped into our StageStatus vocabulary
  via an EXPLICIT, reviewable mapping table (unknown values fail closed to
  FAILED — an unknown state must never look like success).
- ``fetch_step_logs`` -> raw job trace text (structured parsing is the
  Observer's job).
"""

from __future__ import annotations

import hashlib
import time

from ci_agent.adapters.base import (
    CompiledArtifact,
    DispatchRef,
    RunnerAdapter,
    RunnerStatusSnapshot,
    StageStatusView,
)
from ci_agent.adapters.errors import GitLabAPIError
from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.gitlab_ci.client import GitLabClient
from ci_agent.adapters.gitlab_ci.compiler import PIPELINE_FILE_NAME, compile_to_gitlab_ci
from ci_agent.core.models.common import StageStatus
from ci_agent.core.models.execution_plan import ExecutionPlan

BRANCH_PREFIX = "ci-agent/"

# Pipeline-id resolution fallback (bounded retry, same pattern/limits as the
# GitHub adapter: max 5 attempts with linear backoff).
PIPELINE_ID_RESOLUTION_ATTEMPTS = 5
PIPELINE_ID_RESOLUTION_BACKOFF_SECONDS = 1.0

# --- Explicit, reviewable status-vocabulary mapping table (batch DoD). -----
# GitLab pipeline/job status -> StageStatus. GitLab uses "canceled" (one L).
# Unknown values map to FAILED — fail-closed (an unknown state must never
# look like success). "manual" jobs never occur in compiled pipelines and
# therefore fail closed rather than being guessed at.
GITLAB_STATUS_TO_STAGE_STATUS: dict[str, StageStatus] = {
    "created": StageStatus.PENDING,
    "pending": StageStatus.PENDING,
    "running": StageStatus.RUNNING,
    "success": StageStatus.PASSED,
    "failed": StageStatus.FAILED,
    "canceled": StageStatus.CANCELLED,
    "skipped": StageStatus.SKIPPED,
}

# Pipeline statuses that end the pipeline (poll_status.completed).
GITLAB_TERMINAL_STATUSES: frozenset[str] = frozenset({"success", "failed", "canceled", "skipped"})

# The always-run summary job — not a stage (same convention as GitHub's).
RESULTS_JOB_NAME = "ci-agent-results"


def map_gitlab_status(status: str) -> StageStatus:
    """Map a GitLab pipeline/job status to StageStatus (fail-closed)."""
    return GITLAB_STATUS_TO_STAGE_STATUS.get(status, StageStatus.FAILED)


class GitLabCIAdapter(RunnerAdapter):
    """Adapter #2: GitLab CI (Report Section 12 — adapters, not vendor logic)."""

    def __init__(
        self,
        client: GitLabClient,
        registry: CommandTemplateRegistry | None = None,
        pipeline_id_resolution_attempts: int = PIPELINE_ID_RESOLUTION_ATTEMPTS,
        pipeline_id_resolution_backoff_seconds: float = PIPELINE_ID_RESOLUTION_BACKOFF_SECONDS,
    ) -> None:
        self._client = client
        self._registry = registry or CommandTemplateRegistry()
        self._attempts = pipeline_id_resolution_attempts
        self._backoff = pipeline_id_resolution_backoff_seconds

    # ------------------------------------------------------------------ compile

    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
        """Compile the plan into ``.gitlab-ci.yml`` text.

        Requires generic metadata keys ``repository`` and ``source_sha`` (the
        dispatch coordinates an ExecutionPlan intentionally does not carry).
        """
        metadata = metadata or {}
        missing = [key for key in ("repository", "source_sha") if not metadata.get(key)]
        if missing:
            raise ValueError(f"compile metadata is missing required keys: {missing}")
        yaml_text = compile_to_gitlab_ci(plan, self._registry)
        digest = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()
        return CompiledArtifact(
            kind="gitlab_ci_pipeline",
            content=yaml_text,
            content_hash=f"sha256:{digest}",
            metadata={**metadata, "file_path": PIPELINE_FILE_NAME},
        )

    # ----------------------------------------------------------------- dispatch

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        """Create the ci-agent branch, commit the pipeline file, trigger it."""
        project_id = artifact.metadata["repository"]
        source_sha = artifact.metadata["source_sha"]
        file_path = artifact.metadata.get("file_path", PIPELINE_FILE_NAME)
        branch = f"{BRANCH_PREFIX}{run_id}"

        self._client.create_branch(project_id, branch, source_sha)
        self._client.create_or_update_file(
            project_id,
            file_path,
            artifact.content,
            branch,
            commit_message=f"ci-agent: pipeline for run {run_id}",
        )
        pipeline = self._client.trigger_pipeline(project_id, branch)

        external_run_id = self._resolve_pipeline_id(project_id, branch, pipeline)
        return DispatchRef(
            run_id=run_id,
            repository=project_id,
            branch=branch,
            external_run_id=external_run_id,
            workflow_ref=file_path,
        )

    def _resolve_pipeline_id(
        self, project_id: str, branch: str, trigger_response: dict[str, object]
    ) -> str | None:
        """Resolve the runner-native pipeline id.

        Primary path: GitLab's trigger endpoint returns the created pipeline
        synchronously. Fallback (defensive): the GitHub-style bounded retry
        over the branch's pipeline list — max 5 attempts, linear backoff.
        """
        raw_id = trigger_response.get("id")
        if raw_id is not None and str(raw_id):
            return str(raw_id)
        for attempt in range(self._attempts):
            if attempt:
                time.sleep(self._backoff * attempt)
            for pipeline in self._client.list_pipelines(project_id, branch):
                if pipeline.get("ref") == branch:
                    return str(pipeline.get("id"))
        return None

    # -------------------------------------------------------------- poll_status

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        """Fetch the pipeline + its jobs, mapped into our vocabulary."""
        if not dispatch_ref.external_run_id:
            raise ValueError(
                f"dispatch_ref for run {dispatch_ref.run_id} has no external_run_id yet"
            )
        project_id = dispatch_ref.repository
        pipeline = self._client.get_pipeline(project_id, dispatch_ref.external_run_id)
        raw_status = str(pipeline.get("status", ""))
        status = map_gitlab_status(raw_status)
        completed = raw_status in GITLAB_TERMINAL_STATUSES

        stages: list[StageStatusView] = []
        for job in self._client.get_pipeline_jobs(project_id, dispatch_ref.external_run_id):
            name = str(job.get("name", ""))
            if name == RESULTS_JOB_NAME:
                continue  # the summary job, not a stage
            stages.append(
                StageStatusView(
                    stage_id=name,  # compiled jobs are named exactly <stage_id>
                    status=map_gitlab_status(str(job.get("status", ""))),
                    raw_status=str(job.get("status", "")),
                    raw_conclusion=None,
                )
            )

        return RunnerStatusSnapshot(
            run_id=dispatch_ref.run_id,
            dispatch_ref=dispatch_ref,
            status=status,
            completed=completed,
            stages=stages,
            raw={"pipeline": pipeline},
        )

    # ------------------------------------------------------------ step logs

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        """Return the raw trace of the job named ``step_id`` (stage id).

        Raises GitLabAPIError when the pipeline id is unresolved or the job
        cannot be found.
        """
        if not dispatch_ref.external_run_id:
            raise GitLabAPIError(
                f"cannot fetch logs for run {dispatch_ref.run_id}: "
                "external run id not resolved yet"
            )
        for job in self._client.get_pipeline_jobs(
            dispatch_ref.repository, dispatch_ref.external_run_id
        ):
            if str(job.get("name", "")) == step_id:
                return self._client.get_job_log(dispatch_ref.repository, str(job["id"]))
        raise GitLabAPIError(
            f"job {step_id!r} not found in pipeline {dispatch_ref.external_run_id} "
            f"for run {dispatch_ref.run_id}"
        )


__all__ = [
    "GITLAB_STATUS_TO_STAGE_STATUS",
    "GitLabCIAdapter",
    "map_gitlab_status",
]
