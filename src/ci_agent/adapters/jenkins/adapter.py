"""Jenkins runner adapter (Batch 8, Task B; Report Sections 4.2 and 12).

Implements the generic :class:`RunnerAdapter` seam for Jenkins — the
interface is implemented as written, never extended (conformance-tested).

**Polling-only for MVP (deliberate, documented):** Jenkins can push events
to an external URL via the Notification Plugin or a generic webhook plugin,
but that is configured at the JENKINS SERVER level, not in the compiled
pipeline — an ingress endpoint for it would be infrastructure-dependent
fiction. This adapter therefore relies on POLLING (the Batch 4
``reconciliation`` CLI pattern) for observation, and the compiled
Jenkinsfile accordingly emits NO ``ci-agent-results`` artifact step: result
collection uses the Jenkins build RESULT API (``get_build``), not a
pipeline-uploaded artifact. This difference from the GitHub/GitLab pattern
is documented in NOTES.md.

Dispatch model: one Jenkins job named ``ci-agent-<run_id>`` whose config XML
embeds the compiled declarative Jenkinsfile; a build is triggered and the
build number resolved by polling the queue item (bounded retry, max 5
attempts, linear backoff — the same resolution pattern as the other
adapters). ``DispatchRef.branch`` carries the ``ci-agent/<run_id>`` dispatch
label convention (Jenkins has no git branch here — the job IS the
execution); ``DispatchRef.repository`` carries the job name, the
runner-native execution identity.
"""

from __future__ import annotations

import hashlib
import time
from xml.sax.saxutils import escape

from ci_agent.adapters.base import (
    CompiledArtifact,
    DispatchRef,
    RunnerAdapter,
    RunnerStatusSnapshot,
)
from ci_agent.adapters.errors import JenkinsAPIError
from ci_agent.adapters.github_actions.command_template_registry import CommandTemplateRegistry
from ci_agent.adapters.jenkins.client import JenkinsClient
from ci_agent.adapters.jenkins.compiler import compile_to_jenkinsfile
from ci_agent.core.models.common import StageStatus
from ci_agent.core.models.execution_plan import ExecutionPlan

BRANCH_PREFIX = "ci-agent/"
JOB_NAME_PREFIX = "ci-agent-"

# Build-number resolution via queue-item polling (bounded retry, same
# pattern/limits as the other adapters: max 5 attempts, linear backoff).
BUILD_NUMBER_RESOLUTION_ATTEMPTS = 5
BUILD_NUMBER_RESOLUTION_BACKOFF_SECONDS = 1.0

# --- Explicit, reviewable status-vocabulary mapping table (batch DoD). -----
# Jenkins build result -> StageStatus. A null result while ``building`` is
# true maps to RUNNING; a null result on a non-building job fails closed to
# FAILED (never "looks like success"). UNSTABLE (test failures) maps to
# FAILED — an unstable build is not a pass.
JENKINS_RESULT_TO_STAGE_STATUS: dict[str | None, StageStatus] = {
    "SUCCESS": StageStatus.PASSED,
    "FAILURE": StageStatus.FAILED,
    "UNSTABLE": StageStatus.FAILED,
    "ABORTED": StageStatus.CANCELLED,
    "NOT_BUILT": StageStatus.SKIPPED,
}


def map_jenkins_result(result: str | None, building: bool) -> StageStatus:
    """Map a Jenkins build (result, building) pair to StageStatus (fail-closed)."""
    if building:
        return StageStatus.RUNNING
    return JENKINS_RESULT_TO_STAGE_STATUS.get(result, StageStatus.FAILED)


def job_name_for_run(run_id: str) -> str:
    """The Jenkins job name for a run (run ids are uuid-safe)."""
    return f"{JOB_NAME_PREFIX}{run_id}"


def build_job_config_xml(jenkinsfile: str, run_id: str) -> str:
    """Wrap a compiled Jenkinsfile in a flow-definition job config XML.

    The pipeline script is embedded verbatim (XML-escaped); ``sandbox`` is
    true (script-security sandboxed execution — least privilege posture).
    """
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        '<flow-definition plugin="workflow-job">\n'
        f"  <description>ci-agent run {escape(run_id)}</description>\n"
        "  <keepDependencies>false</keepDependencies>\n"
        '  <definition class="CpsFlowDefinition" plugin="workflow-cps">\n'
        f"    <script>{escape(jenkinsfile)}</script>\n"
        "    <sandbox>true</sandbox>\n"
        "  </definition>\n"
        "  <triggers/>\n"
        "  <disabled>false</disabled>\n"
        "</flow-definition>\n"
    )


class JenkinsAdapter(RunnerAdapter):
    """Adapter #3: Jenkins, polling-only for MVP (Report Section 12)."""

    def __init__(
        self,
        client: JenkinsClient,
        registry: CommandTemplateRegistry | None = None,
        build_number_resolution_attempts: int = BUILD_NUMBER_RESOLUTION_ATTEMPTS,
        build_number_resolution_backoff_seconds: float = BUILD_NUMBER_RESOLUTION_BACKOFF_SECONDS,
    ) -> None:
        self._client = client
        self._registry = registry or CommandTemplateRegistry()
        self._attempts = build_number_resolution_attempts
        self._backoff = build_number_resolution_backoff_seconds

    # ------------------------------------------------------------------ compile

    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
        """Compile the plan into declarative Jenkinsfile text.

        Requires generic metadata keys ``repository`` and ``source_sha`` (the
        dispatch coordinates an ExecutionPlan intentionally does not carry).
        """
        metadata = metadata or {}
        missing = [key for key in ("repository", "source_sha") if not metadata.get(key)]
        if missing:
            raise ValueError(f"compile metadata is missing required keys: {missing}")
        jenkinsfile = compile_to_jenkinsfile(plan, self._registry)
        digest = hashlib.sha256(jenkinsfile.encode("utf-8")).hexdigest()
        return CompiledArtifact(
            kind="jenkins_declarative_pipeline",
            content=jenkinsfile,
            content_hash=f"sha256:{digest}",
            metadata={**metadata, "job_name_prefix": JOB_NAME_PREFIX},
        )

    # ----------------------------------------------------------------- dispatch

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        """Create (or update) the run's job, trigger a build, resolve its number."""
        job_name = job_name_for_run(run_id)
        config_xml = build_job_config_xml(artifact.content, run_id)
        self._client.create_job(job_name, config_xml)
        queue_id = self._client.build_job(job_name)
        external_run_id = self._resolve_build_number(queue_id)
        return DispatchRef(
            run_id=run_id,
            repository=job_name,  # the runner-native execution identity
            branch=f"{BRANCH_PREFIX}{run_id}",  # dispatch label convention
            external_run_id=external_run_id,
            workflow_ref="Jenkinsfile (inline in job config)",
        )

    def _resolve_build_number(self, queue_id: int) -> str | None:
        """Poll the queue item until the build number appears (bounded retry)."""
        for attempt in range(self._attempts):
            if attempt:
                time.sleep(self._backoff * attempt)
            item = self._client.get_queue_item(queue_id)
            executable = item.get("executable") or {}
            number = executable.get("number")
            if number is not None and str(number):
                return str(number)
        return None  # unresolved is recorded, not fatal (same as GitHub)

    # -------------------------------------------------------------- poll_status

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        """Fetch the build result, mapped into our vocabulary.

        MVP limitation (documented in NOTES.md): per-STAGE status on Jenkins
        requires the wfapi/pipeline-graph endpoints; ``stages`` is therefore
        empty and the OVERALL build result drives the run-level status the
        state machine consumes. Reconciliation via polling remains correct
        because the orchestrator advances on run-level outcomes.
        """
        if not dispatch_ref.external_run_id:
            raise ValueError(
                f"dispatch_ref for run {dispatch_ref.run_id} has no external_run_id yet"
            )
        build = self._client.get_build(dispatch_ref.repository, dispatch_ref.external_run_id)
        building = bool(build.get("building"))
        result = build.get("result")
        return RunnerStatusSnapshot(
            run_id=dispatch_ref.run_id,
            dispatch_ref=dispatch_ref,
            status=map_jenkins_result(result if isinstance(result, str) else None, building),
            completed=not building,
            stages=[],  # see docstring: run-level polling for MVP
            raw={"build": build},
        )

    # ------------------------------------------------------------ step logs

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        """Return the build's console log (raw text; per-step filtering is
        the Observer's job — Jenkins console output interleaves all stages)."""
        if not dispatch_ref.external_run_id:
            raise JenkinsAPIError(
                f"cannot fetch logs for run {dispatch_ref.run_id}: "
                "external run id not resolved yet"
            )
        return self._client.get_build_log(dispatch_ref.repository, dispatch_ref.external_run_id)


__all__ = [
    "JENKINS_RESULT_TO_STAGE_STATUS",
    "JenkinsAdapter",
    "build_job_config_xml",
    "job_name_for_run",
    "map_jenkins_result",
]
