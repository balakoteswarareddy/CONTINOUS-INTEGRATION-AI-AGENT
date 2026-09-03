"""Jenkins runner adapter (Batch 8, Task C; Report Section 12).

Adapter #3 on the vendor-neutral :class:`RunnerAdapter` seam:

- ``compile``     -> Jenkinsfile (compiler.py) in a CompiledArtifact.
- ``dispatch``    -> the pipeline file is committed by the SCM integration the
  operator configured on the Jenkins job (documented MVP: ci-agent seeds the
  job's pipeline script via the job config API is OUT of scope — flagged);
  dispatch triggers a build with ``CI_AGENT_RUN_ID``/``CI_AGENT_PUBLISH_REF``
  parameters and resolves the build number through the queue API (bounded
  retry, same discipline as GitHub's run-id resolution).
- ``poll_status`` -> ``wfapi/describe`` stage statuses mapped via an explicit,
  fail-closed table.
- ``download_stage_scan_artifact`` -> Batch 6 report contract from the
  ``ci-agent-scan-<stage_id>`` artifact directory.
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
from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.github_actions.compiler import scan_artifact_name
from ci_agent.adapters.jenkins.client import JenkinsAPIError, JenkinsClient
from ci_agent.adapters.jenkins.compiler import compile_to_jenkinsfile
from ci_agent.core.models.common import StageStatus
from ci_agent.core.models.execution_plan import ExecutionPlan

BRANCH_PREFIX = "ci-agent/"  # semantic parity; Jenkins has no branch concept

# Run-id (build number) resolution after triggering (bounded, batch discipline).
BUILD_RESOLUTION_ATTEMPTS = 5
BUILD_RESOLUTION_BACKOFF_SECONDS = 1.0

# Jenkins wfapi stageStatus -> StageStatus. Explicit table; unknown -> FAILED.
JENKINS_STAGE_STATUS_TO_STAGE_STATUS: dict[str, StageStatus] = {
    "SUCCESS": StageStatus.PASSED,
    "FAILED": StageStatus.FAILED,
    "ABORTED": StageStatus.CANCELLED,
    "NOT_BUILT": StageStatus.SKIPPED,
    "PAUSED": StageStatus.PENDING,
    "SKIPPED_FOR_FAILURE": StageStatus.SKIPPED,
}

# Jenkins build result -> StageStatus (top level).
JENKINS_BUILD_RESULT_TO_STAGE_STATUS: dict[str, StageStatus] = {
    "SUCCESS": StageStatus.PASSED,
    "FAILURE": StageStatus.FAILED,
    "UNSTABLE": StageStatus.FAILED,
    "ABORTED": StageStatus.CANCELLED,
    "NOT_BUILT": StageStatus.SKIPPED,
}


def map_jenkins_stage_status(status: str) -> StageStatus:
    """Map a Jenkins wfapi stage status; unknown -> FAILED (fail-closed)."""
    return JENKINS_STAGE_STATUS_TO_STAGE_STATUS.get(status, StageStatus.FAILED)


class JenkinsAdapter(RunnerAdapter):
    """Adapter #3: Jenkins (Section 12 — adapters, not vendor logic)."""

    provider = "jenkins"

    def __init__(
        self,
        client: JenkinsClient,
        registry: CommandTemplateRegistry | None = None,
        build_resolution_attempts: int = BUILD_RESOLUTION_ATTEMPTS,
        build_resolution_backoff_seconds: float = BUILD_RESOLUTION_BACKOFF_SECONDS,
    ) -> None:
        self._client = client
        self._registry = registry or CommandTemplateRegistry()
        self._attempts = build_resolution_attempts
        self._backoff = build_resolution_backoff_seconds

    # ------------------------------------------------------------------ compile

    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
        metadata = metadata or {}
        missing = [key for key in ("repository", "source_sha") if not metadata.get(key)]
        if missing:
            raise ValueError(f"compile metadata is missing required keys: {missing}")
        content = compile_to_jenkinsfile(plan, self._registry)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return CompiledArtifact(
            kind="jenkins_pipeline",
            content=content,
            content_hash=f"sha256:{digest}",
            metadata={**metadata, "jenkinsfile": "Jenkinsfile"},
        )

    # ----------------------------------------------------------------- dispatch

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        """Trigger a parameterized build carrying the run identity.

        The compiled artifact's content is delivered to the Jenkins job by
        the operator's SCM/pipeline-script provisioning (OUT of the API's
        reach without job-config write access — flagged in NOTES.md); the
        control plane passes the artifact hash as a build parameter so the
        job can pin/verify the exact pipeline it runs.
        """
        build_number = self._trigger_and_resolve(
            parameters={
                "CI_AGENT_RUN_ID": run_id,
                "CI_AGENT_PIPELINE_HASH": artifact.content_hash,
                "CI_AGENT_SOURCE_SHA": artifact.metadata.get("source_sha", ""),
            }
        )
        return DispatchRef(
            run_id=run_id,
            repository=artifact.metadata["repository"],
            branch=f"{BRANCH_PREFIX}{run_id}",  # semantic label only
            external_run_id=build_number,
            workflow_ref=f"{self._client.job_path()}/{build_number}",
        )

    def _trigger_and_resolve(self, parameters: dict[str, str]) -> str:
        queue_location = self._client.trigger_build(parameters)
        for attempt in range(self._attempts):
            if attempt:
                time.sleep(self._backoff * attempt)
            item = self._client.get_queue_item(queue_location)
            build = item.get("executable") or {}
            number = build.get("number")
            if number is not None:
                return str(number)
        raise JenkinsAPIError(
            f"Jenkins build number did not resolve after {self._attempts} attempts"
        )

    # -------------------------------------------------------------- poll_status

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        build_number = dispatch_ref.external_run_id
        if not build_number:
            raise ValueError(
                f"dispatch_ref for run {dispatch_ref.run_id} has no external_run_id yet"
            )
        build = self._client.get_build(build_number)
        building = bool(build.get("building"))
        raw_result = str(build.get("result", "") or "")
        if building:
            status = StageStatus.RUNNING
            completed = False
        else:
            status = JENKINS_BUILD_RESULT_TO_STAGE_STATUS.get(raw_result, StageStatus.FAILED)
            completed = raw_result != ""

        stages: list[StageStatusView] = []
        for stage in self._client.describe_build_stages(build_number):
            name = str(stage.get("name", ""))
            if not name or name.startswith("ci-agent"):  # wrapper stages, not ours
                continue
            stages.append(
                StageStatusView(
                    stage_id=name,  # Jenkins stages were named after stage ids
                    status=map_jenkins_stage_status(str(stage.get("status", ""))),
                    raw_status=str(stage.get("status", "")),
                )
            )
        return RunnerStatusSnapshot(
            run_id=dispatch_ref.run_id,
            dispatch_ref=dispatch_ref,
            status=status,
            completed=completed,
            stages=stages,
            raw={"build": build},
        )

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        build_number = dispatch_ref.external_run_id
        if not build_number:
            raise ValueError("dispatch_ref has no external_run_id yet")
        response = self._client.request(
            "GET", f"{self._client.job_path()}/{build_number}/logText/progressiveText"
        )
        return response.text

    # ------------------------------------------------- report artifact contract

    def download_stage_scan_artifact(
        self, dispatch_ref: DispatchRef, stage_id: str
    ) -> dict[str, str]:
        """Batch 6 contract, Jenkins flavor: fetch the archived reports of the
        stage under ``ci-agent-scan-<stage_id>/``; {} when absent."""
        build_number = dispatch_ref.external_run_id
        if not build_number:
            return {}
        prefix = scan_artifact_name(stage_id) + "/"
        contents: dict[str, str] = {}
        build = self._client.get_build(build_number)
        for artifact in build.get("artifacts", []) or []:
            path = str(artifact.get("relativePath", ""))
            if path.startswith(prefix) and path.endswith(".json"):
                blob = self._client.download_artifact(build_number, path)
                contents[path.rsplit("/", 1)[-1]] = blob.decode("utf-8")
        return contents


__all__ = ["JENKINS_STAGE_STATUS_TO_STAGE_STATUS", "JenkinsAdapter", "map_jenkins_stage_status"]
