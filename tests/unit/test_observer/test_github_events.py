"""Unit tests: workflow_run / check_run events through /webhooks/github (Batch 4)."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.ingress.app import create_app

SECRET = "observer-test-secret"


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture()
def client(tmp_path: Path):
    settings = Settings(
        env="local",
        database_url=f"sqlite:///{tmp_path / 'observer-test.db'}",
        github_webhook_secret=SECRET,
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def create_run(client: TestClient, source_sha: str = "abc123", delivery: str = "d-create") -> str:
    """Create a run through the normal PR webhook path and mark it dispatched."""
    payload = {
        "action": "opened",
        "pull_request": {"head": {"ref": "feature/x", "sha": source_sha}},
        "repository": {"full_name": "example-org/payments-api"},
    }
    body = json.dumps(payload).encode()
    response = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": _sign(body),
        },
    )
    assert response.status_code == 202
    run_id = response.json()["run_id"]

    # Simulate the adapter's dispatch bookkeeping (branch + external run id).
    store = client.app.state.audit_store  # type: ignore[attr-defined]
    run = store.get_run(run_id)
    session_factory = store._session_factory
    with session_factory() as session:
        run.dispatch_branch = f"ci-agent/{run_id}"
        run.external_run_id = "9001"
        session.add(run)
        session.commit()
    return run_id


def post_event(client: TestClient, event: str, payload: dict, delivery: str) -> object:
    body = json.dumps(payload).encode()
    return client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": event,
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": _sign(body),
        },
    )


class TestWorkflowRunEvents:
    def test_in_progress_then_completed_updates_records(self, client: TestClient) -> None:
        run_id = create_run(client)
        branch = f"ci-agent/{run_id}"

        first = post_event(
            client,
            "workflow_run",
            {
                "workflow_run": {
                    "head_branch": branch,
                    "status": "in_progress",
                    "conclusion": None,
                    "logs_url": "https://logs/run/9001",
                },
                "repository": {"full_name": "example-org/payments-api"},
            },
            "d-wf-1",
        )
        second = post_event(
            client,
            "workflow_run",
            {
                "workflow_run": {
                    "head_branch": branch,
                    "status": "completed",
                    "conclusion": "success",
                },
                "repository": {"full_name": "example-org/payments-api"},
            },
            "d-wf-2",
        )

        assert first.status_code == 200
        assert second.status_code == 200
        observer = client.app.state.observer  # type: ignore[attr-defined]
        record = observer.get_stage_record(run_id, "workflow")
        assert record is not None
        assert record.status == "passed"
        assert record.logs_ref == "https://logs/run/9001"
        timeline = observer.get_run_timeline(run_id)
        # One row per (run, stage), updated in place: running -> passed.
        assert len(timeline) == 1
        assert timeline[0].status == "passed"

    def test_failed_conclusion_maps_to_failed(self, client: TestClient) -> None:
        run_id = create_run(client, source_sha="def456", delivery="d-create-2")

        response = post_event(
            client,
            "workflow_run",
            {
                "workflow_run": {
                    "head_branch": f"ci-agent/{run_id}",
                    "status": "completed",
                    "conclusion": "failure",
                },
                "repository": {"full_name": "example-org/payments-api"},
            },
            "d-wf-3",
        )

        assert response.status_code == 200
        observer = client.app.state.observer  # type: ignore[attr-defined]
        assert observer.get_stage_record(run_id, "workflow").status == "failed"

    def test_non_ci_agent_branch_is_audited_unmatched(self, client: TestClient) -> None:
        response = post_event(
            client,
            "workflow_run",
            {
                "workflow_run": {
                    "head_branch": "feature/x",
                    "status": "completed",
                    "conclusion": "success",
                },
                "repository": {"full_name": "example-org/payments-api"},
            },
            "d-wf-4",
        )

        assert response.status_code == 200
        store = client.app.state.audit_store  # type: ignore[attr-defined]
        events = [e.event_type for e in store.get_audit_trail("observer:unmatched")]
        assert "observer_event_unmatched" in events


class TestCheckRunEvents:
    def test_check_run_maps_to_stage_transition(self, client: TestClient) -> None:
        run_id = create_run(client, source_sha="abcsha", delivery="d-create-3")

        running = post_event(
            client,
            "check_run",
            {
                "check_run": {
                    "name": "sast",
                    "status": "in_progress",
                    "conclusion": None,
                    "head_sha": "abcsha",
                },
                "repository": {"full_name": "example-org/payments-api"},
            },
            "d-cr-1",
        )
        failed = post_event(
            client,
            "check_run",
            {
                "check_run": {
                    "name": "sast",
                    "status": "completed",
                    "conclusion": "failure",
                    "head_sha": "abcsha",
                },
                "repository": {"full_name": "example-org/payments-api"},
            },
            "d-cr-2",
        )

        assert running.status_code == 200
        assert failed.status_code == 200
        observer = client.app.state.observer  # type: ignore[attr-defined]
        record = observer.get_stage_record(run_id, "sast")
        assert record is not None
        assert record.status == "failed"

    def test_results_job_is_ignored(self, client: TestClient) -> None:
        run_id = create_run(client, source_sha="resultsha", delivery="d-create-4")

        response = post_event(
            client,
            "check_run",
            {
                "check_run": {
                    "name": "ci-agent-results",
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "resultsha",
                },
                "repository": {"full_name": "example-org/payments-api"},
            },
            "d-cr-3",
        )

        assert response.status_code == 200
        observer = client.app.state.observer  # type: ignore[attr-defined]
        stage_ids = [r.stage_id for r in observer.get_run_timeline(run_id)]
        assert "ci-agent-results" not in stage_ids
        assert stage_ids == []  # nothing was recorded for this event


class TestDuplicateAndSecurity:
    def test_duplicate_delivery_is_idempotent_noop(self, client: TestClient) -> None:
        run_id = create_run(client, source_sha="dupsha", delivery="d-create-5")
        payload = {
            "workflow_run": {
                "head_branch": f"ci-agent/{run_id}",
                "status": "completed",
                "conclusion": "success",
            },
            "repository": {"full_name": "example-org/payments-api"},
        }

        first = post_event(client, "workflow_run", payload, "d-dup")
        second = post_event(client, "workflow_run", payload, "d-dup")

        assert first.status_code == 200
        assert second.status_code == 200
        assert "duplicate" in second.json()["detail"]
        observer = client.app.state.observer  # type: ignore[attr-defined]
        # Only ONE workflow record (the duplicate did nothing).
        assert len([r for r in observer.get_run_timeline(run_id) if r.stage_id == "workflow"]) == 1

    def test_disallowed_repository_rejected_403(self, client: TestClient) -> None:
        response = post_event(
            client,
            "workflow_run",
            {
                "workflow_run": {
                    "head_branch": "ci-agent/run-x",
                    "status": "completed",
                    "conclusion": "success",
                },
                "repository": {"full_name": "rogue-org/stealer"},
            },
            "d-cr-rogue",
        )

        assert response.status_code == 403

    def test_bad_signature_rejected_401(self, client: TestClient) -> None:
        payload = {"workflow_run": {}, "repository": {"full_name": "example-org/payments-api"}}
        body = json.dumps(payload).encode()
        response = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-GitHub-Delivery": "d-badsig",
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
            },
        )

        assert response.status_code == 401
