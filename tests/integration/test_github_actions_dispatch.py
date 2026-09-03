"""Integration: real GitHub Actions dispatch (Batch 4 DoD 4).

Requires real credentials against a disposable test repository:

    export GITHUB_PAT=github_pat_xxx            # or GitHub App vars
    export CI_AGENT_TEST_REPO=your-org/ci-agent-test-repo
    pytest -m integration -v

Setup steps (README documents these too):
1. Create an empty disposable GitHub repository (any default branch name).
2. Create a fine-grained PAT with Contents: read+write and Actions: write on
   that repository only.
3. Ensure the repository allowlist in
   src/ci_agent/governance/catalog/policies/identity_policy.yaml covers the
   test repo (add your-org/ci-agent-test-repo).
4. Run the command above. The test compiles a minimal plan, dispatches it on a
   ci-agent/<run_id> branch, resolves the run id, and polls to completion.

Skipped automatically when the credentials are absent.
"""

from __future__ import annotations

import os
import time
from fnmatch import fnmatch

import pytest

from ci_agent.adapters.github_actions.adapter import GitHubActionsAdapter
from ci_agent.adapters.github_actions.client import GitHubAuthConfig, GitHubClient
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy
from ci_agent.governance import load_policy_file

pytestmark = pytest.mark.integration

TEST_REPO = os.environ.get("CI_AGENT_TEST_REPO", "")


def _credentials_present() -> bool:
    if not TEST_REPO:
        return False
    if os.environ.get("GITHUB_PAT"):
        return True
    return bool(
        os.environ.get("GITHUB_APP_ID")
        and os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")
        and os.environ.get("GITHUB_INSTALLATION_ID")
    )


def _repo_allowlisted() -> bool:
    try:
        patterns = load_policy_file("identity_policy").get("allowed_repositories", [])
    except Exception:
        return False
    return any(fnmatch(TEST_REPO, pattern) for pattern in patterns)


requires_credentials = pytest.mark.skipif(
    not _credentials_present(),
    reason=(
        "set GITHUB_PAT (or GitHub App vars) and CI_AGENT_TEST_REPO "
        "to run the live dispatch test"
    ),
)


def _minimal_plan(source_sha: str) -> ExecutionPlan:
    return ExecutionPlan(
        run_id=f"manual-{int(time.time())}",
        pipeline_spec_ref="sha256:manual",
        resolved_steps=[
            ResolvedStep(
                step_id="checkout.git",
                stage_id="checkout",
                tool_name="git",
                tool_version="2.43",
                container_image=None,
                command_template_id="checkout.default",
                timeout_seconds=120,
                retry_policy=RetryPolicy(),
            ),
            ResolvedStep(
                step_id="format_lint.ruff",
                stage_id="format_lint",
                tool_name="ruff",
                tool_version="0.6.0",
                container_image=None,  # run on the runner VM for the manual test
                command_template_id="lint.ruff",
                timeout_seconds=300,
                retry_policy=RetryPolicy(),
                depends_on=["checkout"],
            ),
        ],
    )


@pytest.fixture(scope="module")
def adapter() -> GitHubActionsAdapter:
    auth = GitHubAuthConfig(
        pat=os.environ.get("GITHUB_PAT"),
        app_id=os.environ.get("GITHUB_APP_ID"),
        private_key_path=os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH"),
        installation_id=os.environ.get("GITHUB_INSTALLATION_ID"),
    )
    client = GitHubClient(auth)
    yield GitHubActionsAdapter(client, run_id_resolution_backoff_seconds=2.0)
    client.close()


@requires_credentials
def test_real_dispatch_and_observation(adapter: GitHubActionsAdapter) -> None:
    assert (
        _repo_allowlisted()
    ), f"{TEST_REPO} must be allow-listed in identity_policy.yaml for the live test"
    head_sha = adapter._client.get_branch_sha(TEST_REPO, adapter._client.get_branch_sha and "main")

    plan = _minimal_plan(head_sha)
    artifact = adapter.compile(plan, metadata={"repository": TEST_REPO, "source_sha": head_sha})
    dispatch_ref = adapter.dispatch(artifact, plan.run_id)

    # The run id was resolved from the Actions API after dispatch.
    assert dispatch_ref.external_run_id, "expected a resolved GitHub run id after dispatch"

    # Poll (bounded) until the run completes; then confirm the snapshot maps cleanly.
    deadline = time.time() + 300
    snapshot = adapter.poll_status(dispatch_ref)
    while not snapshot.completed and time.time() < deadline:
        time.sleep(5)
        snapshot = adapter.poll_status(dispatch_ref)

    assert snapshot.completed, "run did not complete within the bounded window"
    terminal = ["passed", "failed", "cancelled", "skipped"]
    assert snapshot.status.value in terminal, snapshot.status

    # Manual DoD reconciliation: StageExecutionRecord rows reach terminal state.
    from ci_agent.audit.audit_store import AuditStore
    from ci_agent.config.settings import get_settings
    from ci_agent.db.base import create_engine, get_session_factory
    from ci_agent.observer.execution_observer import ExecutionObserver

    settings = get_settings()
    engine = create_engine(settings.database_url)
    factory = get_session_factory(engine)
    store = AuditStore(factory)
    observer = ExecutionObserver(factory, store)
    from ci_agent.observer.reconciliation import reconcile_run

    result = reconcile_run(plan.run_id, adapter=adapter, observer=observer, session_factory=factory)
    assert result.action == "reconciled"
    timeline = observer.get_run_timeline(plan.run_id)
    assert timeline, "expected reconciled stage records"
    engine.dispose()
