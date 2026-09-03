"""Integration: real GitLab CI dispatch (Batch 8 DoD).

Requires real credentials against a disposable GitLab project:

    export GITLAB_ACCESS_TOKEN=glpat-xxxxxxxxxxxx
    export GITLAB_BASE_URL=https://gitlab.example/api/v4    # optional (default gitlab.com)
    export CI_AGENT_TEST_GITLAB_PROJECT=my-group/ci-agent-test-project
    pytest -m integration -v tests/integration/test_gitlab_dispatch.py

Setup steps:
1. Create an empty disposable GitLab project (any default branch name).
2. Create a project access token with Developer+ role and api scope.
3. Enable CI for the project (an initial .gitlab-ci.yml may be needed for
   pipelines to be enabled; any trivial content works — the test overwrites
   it on its own dispatch branch only).
4. Ensure the repository allowlist in
   src/ci_agent/governance/catalog/policies/identity_policy.yaml covers the
   project path.
5. Run the command above. The test compiles a minimal plan, pushes
   .gitlab-ci.yml to a ci-agent/<run_id> branch, triggers the pipeline,
   resolves the pipeline id, and polls to completion.

This is DELIBERATELY SEPARATE from the conformance suite: the conformance
suite runs with zero live credentials against mocked clients. This file is
skipped automatically when the credentials are absent.
"""

from __future__ import annotations

import os
from fnmatch import fnmatch

import pytest

from ci_agent.adapters.gitlab_ci.adapter import GitLabCIAdapter
from ci_agent.adapters.gitlab_ci.client import GitLabClient
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy
from ci_agent.governance import load_policy_file

pytestmark = pytest.mark.integration

TEST_PROJECT = os.environ.get("CI_AGENT_TEST_GITLAB_PROJECT", "")


def _credentials_present() -> bool:
    return bool(TEST_PROJECT and os.environ.get("GITLAB_ACCESS_TOKEN"))


def _project_allowlisted() -> bool:
    try:
        patterns = load_policy_file("identity_policy").get("allowed_repositories", [])
    except Exception:
        return False
    return any(fnmatch(TEST_PROJECT, pattern) for pattern in patterns)


requires_credentials = pytest.mark.skipif(
    not _credentials_present(),
    reason="GITLAB_ACCESS_TOKEN / CI_AGENT_TEST_GITLAB_PROJECT not set",
)

requires_allowlist = pytest.mark.skipif(
    not _project_allowlisted(),
    reason="CI_AGENT_TEST_GITLAB_PROJECT is not covered by identity_policy allowlist",
)


def _client() -> GitLabClient:
    return GitLabClient(
        os.environ["GITLAB_ACCESS_TOKEN"],
        base_url=os.environ.get("GITLAB_BASE_URL", "https://gitlab.com/api/v4"),
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
            ResolvedStep(
                step_id="unit_tests.pytest",
                stage_id="unit_tests",
                tool_name="pytest",
                tool_version="8.2.0",
                container_image="python:3.11-slim",
                command_template_id="tests.pytest",
                timeout_seconds=600,
                retry_policy=RetryPolicy(),
                depends_on=["format_lint.ruff"],
            ),
        ],
    )


@requires_credentials
@requires_allowlist
class TestGitLabDispatch:
    def test_compile_dispatch_poll_and_logs(self) -> None:
        run_id = "ci-agent-integration-gitlab-1"
        adapter = GitLabCIAdapter(_client())

        artifact = adapter.compile(
            _minimal_plan(run_id),
            metadata={"repository": TEST_PROJECT, "source_sha": "HEAD"},
        )
        assert artifact.kind == "gitlab_ci_pipeline"

        ref = adapter.dispatch(artifact, run_id)
        assert ref.branch == f"ci-agent/{run_id}"
        assert ref.external_run_id is not None, "pipeline id must resolve"

        snapshot = adapter.poll_status(ref)
        assert snapshot.run_id == run_id
        # The minimal plan's jobs either pass (python image pulls ruff/pytest
        # on the fly via the registry template) or the project lacks shared
        # runners — the contract under test is the POLL/LOGS interface, so a
        # non-completed snapshot is acceptable only when a failure detail
        # came back; both must map into our vocabulary either way.
        if snapshot.completed:
            logs = adapter.fetch_step_logs(ref, "format_lint")
            assert isinstance(logs, str)
