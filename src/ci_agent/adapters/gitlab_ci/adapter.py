"""GitLab CI runner adapter (Batch 8, Task B; Report Section 12).

Adapter #2 on the vendor-neutral :class:`RunnerAdapter` seam:

- ``compile``      -> ``.gitlab-ci.yml`` (compiler.py) in a CompiledArtifact.
- ``dispatch``     -> dedicated branch ``ci-agent/<run_id>`` from the source
  revision, commit the pipeline file, create a pipeline on that branch, and
  record the pipeline id as the runner-native external id (synchronous — no
  retry loop needed, unlike GitHub's workflow_dispatch).
- ``poll_status``  -> pipeline + its jobs mapped into our StageStatus
  vocabulary via explicit, fail-closed tables.
- ``fetch_step_logs`` -> job trace text.
- ``download_stage_scan_artifact`` -> the Batch 6 report-artifact contract,
  GitLab flavor (job artifacts archive, .json entries extracted).
"""

from __future__ import annotations

import hashlib
import io
import zipfile

from ci_agent.adapters.base import (
    CompiledArtifact,
    DispatchRef,
    RunnerAdapter,
    RunnerStatusSnapshot,
    StageStatusView,
)
from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.gitlab_ci.client import GitLabAPIError, GitLabClient
from ci_agent.adapters.gitlab_ci.compiler import (
    PIPELINE_PATH,
    compile_to_gitlab_ci,
    stage_id_from_job_name,
)
from ci_agent.core.models.common import StageStatus
from ci_agent.core.models.execution_plan import ExecutionPlan

BRANCH_PREFIX = "ci-agent/"

# GitLab pipeline/job status -> StageStatus. Explicit, reviewable table;
# unknown values map to FAILED — an unknown state must never look like success
# (fail-closed, same discipline as the GitHub mapping tables).
GITLAB_STATUS_TO_STAGE_STATUS: dict[str, StageStatus] = {
    "success": StageStatus.PASSED,
    "failed": StageStatus.FAILED,
    "canceled": StageStatus.CANCELLED,
    "cancelled": StageStatus.CANCELLED,
    "skipped": StageStatus.SKIPPED,
    "manual": StageStatus.PENDING,
    "created": StageStatus.QUEUED,
    "waiting_for_resource": StageStatus.QUEUED,
    "preparing": StageStatus.QUEUED,
    "pending": StageStatus.PENDING,
    "scheduled": StageStatus.QUEUED,
    "running": StageStatus.RUNNING,
}


def map_gitlab_status(status: str) -> StageStatus:
    """Map a GitLab pipeline/job status; unknown -> FAILED (fail-closed)."""
    return GITLAB_STATUS_TO_STAGE_STATUS.get(status, StageStatus.FAILED)


# Pipeline-level statuses that mean "no more transitions are coming".
GITLAB_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"success", "failed", "canceled", "cancelled", "skipped"}
)


class GitLabCIAdapter(RunnerAdapter):
    """Adapter #2: GitLab CI (Section 12 — adapters, not vendor logic)."""

    provider = "gitlab_ci"

    def __init__(
        self,
        client: GitLabClient,
        registry: CommandTemplateRegistry | None = None,
    ) -> None:
        self._client = client
        self._registry = registry or CommandTemplateRegistry()

    # ------------------------------------------------------------------ compile

    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
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
            metadata={**metadata, "pipeline_path": PIPELINE_PATH},
        )

    # ----------------------------------------------------------------- dispatch

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        repository = artifact.metadata["repository"]
        source_sha = artifact.metadata["source_sha"]
        branch = f"{BRANCH_PREFIX}{run_id}"

        self._client.create_branch(branch, source_sha)
        commit_sha = self._client.commit_files(
            branch,
            {PIPELINE_PATH: artifact.content},
            commit_message=f"ci-agent: pipeline for run {run_id}",
        )
        pipeline_id = self._client.create_pipeline(branch)
        return DispatchRef(
            run_id=run_id,
            repository=repository,
            branch=branch,
            external_run_id=pipeline_id,
            workflow_ref=f"{PIPELINE_PATH}@{commit_sha}",
        )

    # -------------------------------------------------------------- poll_status

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        """Fetch pipeline + job statuses mapped into our vocabulary."""
        pipeline_id = dispatch_ref.external_run_id
        if not pipeline_id:
            raise ValueError(
                f"dispatch_ref for run {dispatch_ref.run_id} has no external_run_id yet"
            )
        pipeline = self._client.get_pipeline(pipeline_id)
        raw_status = str(pipeline.get("status", ""))
        status = map_gitlab_status(raw_status)
        completed = raw_status in GITLAB_TERMINAL_STATUSES

        stages: list[StageStatusView] = []
        for job in self._client.list_pipeline_jobs(pipeline_id):
            name = str(job.get("name", ""))
            if not name.startswith("stage-"):
                continue  # only ci-agent stage jobs correlate
            stages.append(
                StageStatusView(
                    stage_id=stage_id_from_job_name(name),
                    status=map_gitlab_status(str(job.get("status", ""))),
                    raw_status=str(job.get("status", "")),
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

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        """Fetch the trace of the job named ``stage-<step_id>``."""
        pipeline_id = dispatch_ref.external_run_id
        if not pipeline_id:
            raise ValueError("dispatch_ref has no external_run_id yet")
        target = f"stage-{step_id}"
        for job in self._client.list_pipeline_jobs(pipeline_id):
            if str(job.get("name", "")) == target:
                return self._client.get_job_trace(str(job["id"]))
        raise GitLabAPIError(f"no GitLab job named {target!r} in pipeline {pipeline_id}")

    # ------------------------------------------------- report artifact contract

    def download_stage_scan_artifact(
        self, dispatch_ref: DispatchRef, stage_id: str
    ) -> dict[str, str]:
        """Batch 6 contract, GitLab flavor: {filename: text} for the stage's
        ``ci-agent-scan-<stage_id>`` artifacts; {} when absent (fail-closed
        upstream)."""
        pipeline_id = dispatch_ref.external_run_id
        if not pipeline_id:
            return {}
        # GitLab artifacts attach to the PRODUCING job (named stage-<stage_id>,
        # same convention as the observer correlation); the archive contains
        # exactly that job's artifacts:paths entries.
        target_job = next(
            (
                job
                for job in self._client.list_pipeline_jobs(pipeline_id)
                if str(job.get("name", "")) == f"stage-{stage_id}"
            ),
            None,
        )
        if target_job is None:
            return {}
        blob = self._client.download_job_artifacts(str(target_job["id"]))
        archive = zipfile.ZipFile(io.BytesIO(blob))
        contents: dict[str, str] = {}
        for name in archive.namelist():
            if name.endswith(".json"):
                contents[name] = archive.read(name).decode("utf-8")
        return contents


__all__ = ["GITLAB_STATUS_TO_STAGE_STATUS", "GitLabCIAdapter", "map_gitlab_status"]
