"""GitLab webhook ingestion tests (Batch 8, Task B; Section 7.3/10/12)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.db.models import RunRecord
from ci_agent.ingress.app import create_app

SECRET = "gitlab-hook-secret"
PIPELINE_ID = "9001"


@pytest.fixture()
def client(tmp_path):
    database_path = tmp_path / "gl-hook.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    engine.dispose()
    settings = Settings(
        env="local",
        database_url=f"sqlite:///{database_path}",
        gitlab_webhook_token=SECRET,
    )
    application = create_app(settings)

    # Insulate the orchestrator from real GitHub side effects (mocks only in
    # unit tests): merge-decision publication is recorded, never sent.
    class _RecordingGithub:
        def __init__(self) -> None:
            self.check_runs: list[dict[str, Any]] = []

        def post_check_run(self, repo: str, sha: str, **kwargs: Any) -> dict[str, Any]:
            self.check_runs.append({"repo": repo, "sha": sha, **kwargs})
            return {"id": 1}

    application.state.orchestrator._github = _RecordingGithub()  # type: ignore[attr-defined]
    with TestClient(application) as test_client:
        store = test_client.app.state.audit_store  # type: ignore[attr-defined]
        store.create_run(
            run_id="run-gl-hook",
            project_id="example-org/payments-api",
            repository="example-org/payments-api",
            trigger_type="push",
            source_sha="cafe1234",
        )
        with get_session_factory(engine)() as session:
            run = session.get(RunRecord, "run-gl-hook")
            assert run is not None
            run.runner_provider = "gitlab_ci"
            run.dispatch_branch = "ci-agent/run-gl-hook"
            run.external_run_id = PIPELINE_ID
            run.current_state = "trigger_validated"
            session.commit()
        yield test_client


def _job_payload(
    job_name: str = "stage-sast",
    build_status: str = "success",
    delivery: str = "job-1",
) -> dict[str, Any]:
    return {
        "object_kind": "build",
        "job_id": delivery,
        "build_name": job_name,
        "build_status": build_status,
        "pipeline_id": PIPELINE_ID,
    }


def _post(client: TestClient, payload: dict[str, Any], token: str | None = SECRET) -> Any:
    headers = {"X-Gitlab-Event": "Job Hook"}
    if token is not None:
        headers["X-GITLAB-TOKEN"] = token
    return client.post("/webhooks/gitlab", content=json.dumps(payload).encode(), headers=headers)


def test_missing_token_rejected(client: TestClient) -> None:
    response = _post(client, _job_payload(), token=None)
    assert response.status_code in (401, 403, 500)


def test_wrong_token_rejected(client: TestClient) -> None:
    response = _post(client, _job_payload(), token="wrong-secret")
    assert response.status_code in (401, 403, 500)


def test_job_event_transitions_the_run(client: TestClient) -> None:
    # Legal Phase A order: checkout -> format_lint -> sast.
    for stage in ("stage-checkout", "stage-format_lint", "stage-sast"):
        response = _post(client, _job_payload(stage, "success", delivery=f"job-{stage}"))
        assert response.status_code == 202
        body = response.json()
        assert body["status"] == "accepted"
        assert body["run_id"] == "run-gl-hook"
        assert body["stage_status"] == "passed"

    # The run state machine advanced through the legal sequence.
    session_factory = client.app.state.session_factory  # type: ignore[attr-defined]
    with session_factory() as session:
        run = session.get(RunRecord, "run-gl-hook")
        assert run is not None
        assert run.current_state == "sast_done"


def _run_state(client: TestClient, run_id: str = "run-gl-hook") -> str | None:
    session_factory = client.app.state.session_factory  # type: ignore[attr-defined]
    with session_factory() as session:
        run = session.get(RunRecord, run_id)
        return run.current_state if run is not None else None


def test_failed_job_maps_to_failed(client: TestClient) -> None:
    response = _post(client, _job_payload("stage-checkout", "failed", delivery="job-2"))
    assert response.status_code == 202
    assert response.json()["stage_status"] == "failed"
    assert _run_state(client) == "failed"


def test_duplicate_delivery_is_deduped(client: TestClient) -> None:
    first = _post(client, _job_payload("stage-checkout", "success", delivery="job-dup"))
    second = _post(client, _job_payload(delivery="job-dup"))
    assert first.status_code == 202
    assert second.status_code == 200  # deduped: not re-processed
    assert second.json()["status"] == "duplicate"


def test_non_ci_agent_job_ignored(client: TestClient) -> None:
    response = _post(client, _job_payload("some-unrelated-job", "success", delivery="job-3"))
    assert response.status_code == 200  # webhook succeeded; event ignored
    assert response.json()["status"] == "ignored"


def test_unknown_pipeline_isolated(client: TestClient) -> None:
    """A payload for ANOTHER pipeline must never touch our run (isolation)."""
    payload = _job_payload("stage-checkout", "success", delivery="job-4")
    payload["pipeline_id"] = "999999"
    response = _post(client, payload)
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    # Our run was untouched (never left trigger_validated).
    assert _run_state(client) == "trigger_validated"


def test_non_terminal_status_ignored(client: TestClient) -> None:
    response = _post(client, _job_payload("stage-sast", "running", delivery="job-5"))
    assert response.json()["status"] == "ignored"


def test_other_provider_runs_never_resolved(client: TestClient) -> None:
    """Even with matching ids, a github_actions run is untouched by GitLab."""
    store = client.app.state.audit_store  # type: ignore[attr-defined]
    store.create_run(
        run_id="run-gh-other",
        project_id="example-org/payments-api",
        repository="example-org/payments-api",
        trigger_type="push",
        source_sha="cafe1234",
    )
    session_factory = client.app.state.session_factory  # type: ignore[attr-defined]
    with session_factory() as session:
        run = session.get(RunRecord, "run-gh-other")
        run.external_run_id = PIPELINE_ID  # same id, DIFFERENT provider
        run.runner_provider = "github_actions"
        session.commit()

    response = _post(client, _job_payload("stage-checkout", "success", delivery="job-6"))
    assert response.status_code == 202
    assert response.json()["run_id"] == "run-gl-hook"  # the gitlab_ci run only
