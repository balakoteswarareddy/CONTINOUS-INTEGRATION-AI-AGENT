"""Integration test: webhook -> audit store end to end (Batch 2 DoD 4).

Uses a real SQLite file database, the real governed identity policy, and the
real signature/replay machinery through the full FastAPI stack. This mirrors
the manual curl flow from the Definition of Done.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.ingress.app import create_app

pytestmark = pytest.mark.integration

SECRET = "integration-webhook-secret"


def _sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    settings = Settings(
        env="local",
        database_url=f"sqlite:///{tmp_path / 'integration.db'}",
        github_webhook_secret=SECRET,
    )
    return TestClient(create_app(settings))


def test_full_webhook_flow_creates_run_and_verifiable_chain(client: TestClient) -> None:
    payload = {
        "ref": "refs/heads/main",
        "after": "cafe1234",
        "repository": {"full_name": "example-org/payments-api"},
    }
    body = json.dumps(payload).encode()
    with client as c:
        response = c.post(
            "/webhooks/github",
            content=body,
            headers={
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "integration-delivery-1",
                "X-Hub-Signature-256": _sign(body),
                "Content-Type": "application/json",
            },
        )
        store = c.app.state.audit_store

    assert response.status_code == 202
    run_id = response.json()["run_id"]

    run = store.get_run(run_id)
    assert run is not None
    assert run.trigger_type == "push"
    assert run.source_sha == "cafe1234"

    trail = store.get_audit_trail(run_id)
    assert [entry.event_type for entry in trail] == ["webhook_received", "run_created"]
    assert store.verify_chain(run_id) is True
    assert store.is_delivery_processed("integration-delivery-1") is True


def test_duplicate_and_rejections_audited_across_requests(client: TestClient) -> None:
    payload = {
        "ref": "refs/heads/main",
        "after": "cafe1234",
        "repository": {"full_name": "example-org/payments-api"},
    }
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": "integration-delivery-2",
        "X-Hub-Signature-256": _sign(body),
        "Content-Type": "application/json",
    }
    with client as c:
        first = c.post("/webhooks/github", content=body, headers=headers)
        replay = c.post("/webhooks/github", content=body, headers=headers)
        bad_sig = c.post(
            "/webhooks/github",
            content=body,
            headers={
                **headers,
                "X-GitHub-Delivery": "integration-delivery-3",
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
            },
        )
        store = c.app.state.audit_store

    assert first.status_code == 202
    assert replay.status_code == 200
    assert bad_sig.status_code == 401
    events = [
        entry.event_type for entry in store.get_audit_trail("rejected:integration-delivery-2")
    ]
    assert "duplicate_rejected" in events
    events3 = [
        entry.event_type for entry in store.get_audit_trail("rejected:integration-delivery-3")
    ]
    assert "signature_invalid" in events3
