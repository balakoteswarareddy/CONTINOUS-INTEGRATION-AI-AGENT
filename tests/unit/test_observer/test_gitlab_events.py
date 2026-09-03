"""Unit tests: GitLab pipeline/job event handlers (Batch 8, Task A)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.db.models import RunRecord
from ci_agent.ingress.app import create_app
from ci_agent.observer.execution_observer import ExecutionObserver

GITLAB_TOKEN = "gitlab-webhook-test-token"
PROJECT = "example-org/payments-api"


@pytest.fixture()
def client(tmp_path):
    settings = Settings(
        env="local",
        database_url=f"sqlite:///{tmp_path / 'gitlab-observer.db'}",
        gitlab_webhook_token=GITLAB_TOKEN,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _create_dispatched_run(client: TestClient, run_id: str, branch: str | None = None) -> str:
    """Insert a run record with dispatch coordinates set (as the adapter does)."""
    store = client.app.state.audit_store  # type: ignore[attr-defined]
    store.create_run(
        run_id=run_id,
        project_id=PROJECT,
        repository=PROJECT,
        trigger_type="push",
        source_sha="cafe1234",
    )
    session_factory = store._session_factory
    with session_factory() as session:
        run = session.get(RunRecord, run_id)
        assert run is not None
        run.dispatch_branch = branch or f"ci-agent/{run_id}"
        run.external_run_id = "42"
        session.commit()
    return run_id


def _post_gitlab(
    client: TestClient, event: str, payload: dict, delivery: str, token: str = GITLAB_TOKEN
):
    import json

    return client.post(
        "/webhooks/gitlab",
        content=json.dumps(payload).encode(),
        headers={
            "X-Gitlab-Event": event,
            "X-Gitlab-Event-UUID": delivery,
            "X-Gitlab-Token": token,
        },
    )


class TestJobEvents:
    def test_job_event_records_stage_transition(self, client: TestClient) -> None:
        _create_dispatched_run(client, "run-gl-1")
        payload = {
            "object_kind": "build",
            "ref": "ci-agent/run-gl-1",
            "sha": "cafe1234",
            "build_name": "format_lint",
            "build_status": "success",
            "build_id": 101,
            "pipeline_id": 42,
            "project": {"path_with_namespace": PROJECT},
        }
        response = _post_gitlab(client, "job", payload, "delivery-gl-1")
        assert response.status_code == 200
        assert response.json() == {"status": "observed", "event": "job"}

        observer: ExecutionObserver = client.app.state.observer  # type: ignore[attr-defined]
        record = observer.get_stage_record("run-gl-1", "format_lint")
        assert record is not None
        assert record.status == "passed"

    def test_job_event_running_status(self, client: TestClient) -> None:
        _create_dispatched_run(client, "run-gl-2")
        payload = {
            "object_kind": "build",
            "ref": "ci-agent/run-gl-2",
            "build_name": "sast",
            "build_status": "running",
            "project": {"path_with_namespace": PROJECT},
        }
        response = _post_gitlab(client, "job", payload, "delivery-gl-2")
        assert response.status_code == 200
        observer: ExecutionObserver = client.app.state.observer  # type: ignore[attr-defined]
        record = observer.get_stage_record("run-gl-2", "sast")
        assert record is not None and record.status == "running"

    def test_summary_job_is_skipped(self, client: TestClient) -> None:
        _create_dispatched_run(client, "run-gl-3")
        payload = {
            "object_kind": "build",
            "ref": "ci-agent/run-gl-3",
            "build_name": "ci-agent-results",
            "build_status": "success",
            "project": {"path_with_namespace": PROJECT},
        }
        response = _post_gitlab(client, "job", payload, "delivery-gl-3")
        assert response.status_code == 200
        observer: ExecutionObserver = client.app.state.observer  # type: ignore[attr-defined]
        assert observer.get_stage_record("run-gl-3", "ci-agent-results") is None

    def test_unknown_branch_is_audited_not_matched(self, client: TestClient) -> None:
        payload = {
            "object_kind": "build",
            "ref": "feature/some-branch",
            "build_name": "sast",
            "build_status": "success",
            "project": {"path_with_namespace": PROJECT},
        }
        response = _post_gitlab(client, "job", payload, "delivery-gl-4")
        assert response.status_code == 200
        trail = client.app.state.audit_store.get_audit_trail("observer:unmatched")  # type: ignore[attr-defined]
        assert any(e.event_type == "observer_event_unmatched" for e in trail)


class TestPipelineEvents:
    def test_pipeline_event_records_workflow_pseudo_stage(self, client: TestClient) -> None:
        _create_dispatched_run(client, "run-gl-5")
        payload = {
            "object_kind": "pipeline",
            "object_attributes": {
                "id": 42,
                "ref": "ci-agent/run-gl-5",
                "status": "success",
                "sha": "cafe1234",
            },
            "project": {"path_with_namespace": PROJECT},
        }
        response = _post_gitlab(client, "pipeline", payload, "delivery-gl-5")
        assert response.status_code == 200
        observer: ExecutionObserver = client.app.state.observer  # type: ignore[attr-defined]
        record = observer.get_stage_record("run-gl-5", "workflow")
        assert record is not None and record.status == "passed"

    def test_wave2_branch_also_correlates(self, client: TestClient) -> None:
        """Phase B wave 2 dispatches to the same branch convention — the
        phase_b_wave2_branch column must correlate job events too."""
        store = client.app.state.audit_store  # type: ignore[attr-defined]
        store.create_run(
            run_id="run-gl-6",
            project_id=PROJECT,
            repository=PROJECT,
            trigger_type="push",
            source_sha="cafe1234",
        )
        with store._session_factory() as session:
            run = session.get(RunRecord, "run-gl-6")
            assert run is not None
            run.phase_b_wave2_branch = "ci-agent/run-gl-6"
            session.commit()
        payload = {
            "object_kind": "build",
            "ref": "ci-agent/run-gl-6",
            "build_name": "publish",
            "build_status": "success",
            "project": {"path_with_namespace": PROJECT},
        }
        response = _post_gitlab(client, "job", payload, "delivery-gl-6")
        assert response.status_code == 200
        observer: ExecutionObserver = client.app.state.observer  # type: ignore[attr-defined]
        record = observer.get_stage_record("run-gl-6", "publish")
        assert record is not None and record.status == "passed"


class TestWebhookValidation:
    def test_wrong_token_is_401_and_audited(self, client: TestClient) -> None:
        payload = {
            "object_kind": "pipeline",
            "object_attributes": {"ref": "ci-agent/x", "status": "success"},
            "project": {"path_with_namespace": PROJECT},
        }
        response = _post_gitlab(client, "pipeline", payload, "delivery-bad-1", token="wrong")
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid or unconfigured GitLab webhook token"

    def test_unsupported_event_type_is_400(self, client: TestClient) -> None:
        response = _post_gitlab(
            client,
            "push",
            {"object_kind": "push", "project": {"path_with_namespace": PROJECT}},
            "delivery-bad-2",
        )
        assert response.status_code == 400
        assert "unsupported" in response.json()["detail"]

    def test_invalid_json_is_400(self, client: TestClient) -> None:
        response = client.post(
            "/webhooks/gitlab",
            content=b"not json",
            headers={
                "X-Gitlab-Event": "job",
                "X-Gitlab-Event-UUID": "delivery-bad-3",
                "X-Gitlab-Token": GITLAB_TOKEN,
            },
        )
        assert response.status_code == 400

    def test_duplicate_delivery_is_idempotent_200(self, client: TestClient) -> None:
        _create_dispatched_run(client, "run-gl-7")
        payload = {
            "object_kind": "build",
            "ref": "ci-agent/run-gl-7",
            "build_name": "sast",
            "build_status": "success",
            "project": {"path_with_namespace": PROJECT},
        }
        first = _post_gitlab(client, "job", payload, "delivery-dup-1")
        second = _post_gitlab(client, "job", payload, "delivery-dup-1")
        assert first.status_code == 200
        assert second.status_code == 200
        # Duplicate is audited as a duplicate rejection (idempotent replay).
        store = client.app.state.audit_store  # type: ignore[attr-defined]
        trail = store.get_audit_trail("rejected:delivery-dup-1")
        assert any(e.event_type == "request_rejected" for e in trail)

    def test_disallowed_repository_is_403(self, client: TestClient) -> None:
        payload = {
            "object_kind": "build",
            "ref": "ci-agent/run-x",
            "build_name": "sast",
            "build_status": "success",
            "project": {"path_with_namespace": "rogue-org/evil"},
        }
        response = _post_gitlab(client, "job", payload, "delivery-bad-4")
        assert response.status_code == 403

    def test_missing_uuid_gets_synthetic_id_and_processes(self, client: TestClient) -> None:
        """GitLab always sends X-Gitlab-Event-UUID; a delivery without one is
        still processed safely under a synthetic (uuid) id — the replay guard
        key is stable per request but unique per delivery."""
        _create_dispatched_run(client, "run-gl-8")
        payload = {
            "object_kind": "build",
            "ref": "ci-agent/run-gl-8",
            "build_name": "sast",
            "build_status": "success",
            "project": {"path_with_namespace": PROJECT},
        }
        import json

        response = client.post(
            "/webhooks/gitlab",
            content=json.dumps(payload).encode(),
            headers={"X-Gitlab-Event": "job", "X-Gitlab-Token": GITLAB_TOKEN},
        )
        assert response.status_code == 200
        observer: ExecutionObserver = client.app.state.observer  # type: ignore[attr-defined]
        assert observer.get_stage_record("run-gl-8", "sast") is not None


class TestWiring:
    def test_orchestrator_callback_is_wired(self, client: TestClient) -> None:
        handlers = client.app.state.gitlab_observer_events  # type: ignore[attr-defined]
        # Bound methods create a new object per attribute access, so compare
        # by equality (same function, same instance), not identity.
        assert (
            handlers.on_stage_transition
            == client.app.state.orchestrator.on_stage_transition  # type: ignore[attr-defined]
        )

    def test_handler_lookup_covers_all_dispatch_columns(self, client: TestClient) -> None:
        """_find_run_by_dispatch_branch matches wave-1 OR wave-2 branches."""
        handlers = client.app.state.gitlab_observer_events  # type: ignore[attr-defined]
        store = client.app.state.audit_store  # type: ignore[attr-defined]
        store.create_run(
            run_id="run-cols",
            project_id=PROJECT,
            repository=PROJECT,
            trigger_type="push",
            source_sha="sha",
        )
        with store._session_factory() as session:
            run = session.get(RunRecord, "run-cols")
            assert run is not None
            run.phase_b_branch = "ci-agent/run-cols"
            session.commit()
        found = handlers._find_run_by_dispatch_branch("ci-agent/run-cols")
        assert found is not None and found.run_id == "run-cols"
        assert handlers._find_run_by_dispatch_branch("ci-agent/other") is None
