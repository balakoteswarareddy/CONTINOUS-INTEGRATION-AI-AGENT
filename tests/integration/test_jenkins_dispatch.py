"""Integration: real Jenkins dispatch (Batch 8 DoD).

Requires real credentials against a disposable Jenkins controller:

    export JENKINS_URL=https://jenkins.example.com
    export JENKINS_USER=ci-agent
    export JENKINS_API_TOKEN=xxxxxxxxxxxxxxxx
    export CI_AGENT_TEST_JENKINS_JOB_PREFIX=ci-agent-integration
    pytest -m integration -v tests/integration/test_jenkins_dispatch.py

Setup steps:
1. A Jenkins controller where the user may create jobs (item create) and
   build them. A disposable folder or a unique job prefix is recommended —
   the test creates a job named ``<prefix>-<run_id>``.
2. An API token for that user (Jenkins > Security > API Token).
3. An agent/agent-any available (``agent any``) with a docker-capable or
   python-capable environment for the minimal plan's commands; or relax to a
   plan whose commands run on any default agent.

This is DELIBERATELY SEPARATE from the conformance suite (zero-credential,
mocked clients). Skipped automatically when the credentials are absent.

Jenkins is POLLING-ONLY for the MVP (Batch 8 decision): no Jenkins webhook
ingress exists; completion is observed via reconciliation polling of
get_build — exercised by the poll loop below.
"""

from __future__ import annotations

import os
import time

import pytest

from ci_agent.adapters.jenkins.adapter import JenkinsAdapter
from ci_agent.adapters.jenkins.client import JenkinsClient
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy

pytestmark = pytest.mark.integration

JOB_PREFIX = os.environ.get("CI_AGENT_TEST_JENKINS_JOB_PREFIX", "")

POLL_TIMEOUT_SECONDS = int(os.environ.get("CI_AGENT_TEST_JENKINS_TIMEOUT", "300"))


def _credentials_present() -> bool:
    return bool(
        JOB_PREFIX
        and os.environ.get("JENKINS_URL")
        and os.environ.get("JENKINS_USER")
        and os.environ.get("JENKINS_API_TOKEN")
    )


requires_credentials = pytest.mark.skipif(
    not _credentials_present(),
    reason="JENKINS_URL / JENKINS_USER / JENKINS_API_TOKEN not set",
)


def _client() -> JenkinsClient:
    return JenkinsClient(
        os.environ["JENKINS_URL"],
        os.environ["JENKINS_USER"],
        os.environ["JENKINS_API_TOKEN"],
    )


def _minimal_plan(run_id: str) -> ExecutionPlan:
    return ExecutionPlan(
        run_id=run_id,
        pipeline_spec_ref="sha256:integration",
        resolved_steps=[
            ResolvedStep(
                step_id="format_lint.ruff",
                stage_id="format_lint",
                tool_name="ruff",
                tool_version="0.6.0",
                container_image="python:3.11-slim",
                command_template_id="lint.ruff",
                timeout_seconds=300,
                retry_policy=RetryPolicy(),
                depends_on=[],
            ),
        ],
    )


@requires_credentials
class TestJenkinsDispatch:
    def test_compile_dispatch_poll_and_logs(self) -> None:
        run_id = f"{JOB_PREFIX}-1"
        adapter = JenkinsAdapter(_client())

        artifact = adapter.compile(
            _minimal_plan(run_id),
            metadata={"repository": "ci-agent/jenkins-integration", "source_sha": "HEAD"},
        )
        assert artifact.kind == "jenkins_declarative_pipeline"

        ref = adapter.dispatch(artifact, run_id)
        assert ref.external_run_id is not None, "build number must resolve via queue item"

        deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
        snapshot = adapter.poll_status(ref)
        while not snapshot.completed and time.monotonic() < deadline:
            time.sleep(5)
            snapshot = adapter.poll_status(ref)
        assert snapshot.run_id == run_id
        assert snapshot.completed, f"build did not finish within {POLL_TIMEOUT_SECONDS}s"

        logs = adapter.fetch_step_logs(ref, "format_lint")
        assert isinstance(logs, str)
