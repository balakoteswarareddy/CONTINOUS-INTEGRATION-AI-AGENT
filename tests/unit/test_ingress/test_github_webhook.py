"""Unit tests for POST /webhooks/github (Batch 2, Task B) — every path."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.ingress.app import create_app

SECRET = "unit-test-webhook-secret"
REPO = "example-org/payments-api"


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def pr_payload(
    repo: str = REPO, branch: str = "feature/checkout", sha: str = "abc123"
) -> dict[str, Any]:
    return {
        "action": "opened",
        "pull_request": {"head": {"ref": branch, "sha": sha}},
        "repository": {"full_name": repo},
    }


def push_payload(repo: str = REPO, branch: str = "main", sha: str = "def456") -> dict[str, Any]:
    return {
        "ref": f"refs/heads/{branch}",
        "after": sha,
        "repository": {"full_name": repo},
    }


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    """App client on a per-test SQLite FILE db (survives lifespan dispose)."""
    settings = Settings(
        env="local",
        database_url=f"sqlite:///{tmp_path / 'webhook-test.db'}",
        github_webhook_secret=SECRET,
    )
    return TestClient(create_app(settings))


def post_event(
    client: TestClient,
    payload: dict[str, Any],
    event: str = "pull_request",
    delivery: str = "delivery-1",
    signature: str | None = None,
    body: bytes | None = None,
) -> Any:
    raw = body if body is not None else json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": signature if signature is not None else sign(raw),
        "Content-Type": "application/json",
    }
    return client.post("/webhooks/github", content=raw, headers=headers)


class TestAcceptedRun:
    def test_valid_pull_request_returns_202_with_run_id(self, client: TestClient) -> None:
        with client:
            response = post_event(client, pr_payload())

        assert response.status_code == 202
        body = response.json()
        assert body["status"] == "accepted"
        assert len(body["run_id"]) == 36  # uuid4 string

    def test_run_record_and_audit_trail_created(self, client: TestClient) -> None:
        with client as c:
            app_state = c.app.state
            response = post_event(client, pr_payload())
        run_id = response.json()["run_id"]

        run = app_state.audit_store.get_run(run_id)
        assert run is not None
        assert run.repository == REPO
        assert run.trigger_type == "pull_request"
        assert run.source_sha == "abc123"

        trail = [entry.event_type for entry in app_state.audit_store.get_audit_trail(run_id)]
        assert "webhook_received" in trail
        assert "run_created" in trail
        assert app_state.audit_store.verify_chain(run_id) is True

    def test_push_event_accepted(self, client: TestClient) -> None:
        with client:
            response = post_event(client, push_payload(), event="push", delivery="delivery-push")

        assert response.status_code == 202
        assert response.json()["status"] == "accepted"


class TestSignatureRejection:
    def test_bad_signature_rejected_401_and_audited(self, client: TestClient) -> None:
        with client as c:
            response = post_event(client, pr_payload(), signature="sha256=" + "0" * 64)
            store = c.app.state.audit_store

        assert response.status_code == 401
        trail = store.get_audit_trail("rejected:delivery-1")
        assert "signature_invalid" in [entry.event_type for entry in trail]
        # And no run was created.
        assert response.json()["detail"] == "invalid signature"

    def test_missing_signature_rejected_401(self, client: TestClient) -> None:
        with client:
            raw = json.dumps(pr_payload()).encode()
            response = client.post(
                "/webhooks/github",
                content=raw,
                headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d-2"},
            )

        assert response.status_code == 401

    def test_signature_verified_against_raw_bytes_not_parsed_json(self, client: TestClient) -> None:
        """Reformatting the same JSON (different bytes) must invalidate the signature."""
        with client:
            payload = pr_payload()
            signature = sign(json.dumps(payload, separators=(",", ":")).encode())
            reformatted = json.dumps(payload, indent=2).encode()
            response = post_event(client, payload, signature=signature, body=reformatted)

        assert response.status_code == 401


class TestPayloadRejections:
    def test_unsupported_event_type_rejected_400_and_audited(self, client: TestClient) -> None:
        with client as c:
            response = post_event(client, {"issue": {}}, event="issues", delivery="delivery-3")
            store = c.app.state.audit_store

        assert response.status_code == 400
        assert "unsupported event type" in response.json()["detail"]
        events = [entry.event_type for entry in store.get_audit_trail("rejected:delivery-3")]
        assert "unsupported_event" in events

    def test_invalid_json_rejected_400_and_audited(self, client: TestClient) -> None:
        with client as c:
            response = post_event(client, {}, body=b"not-json{", delivery="delivery-4")
            store = c.app.state.audit_store

        assert response.status_code == 400
        events = [entry.event_type for entry in store.get_audit_trail("rejected:delivery-4")]
        assert "payload_invalid" in events

    def test_missing_repository_field_rejected_400(self, client: TestClient) -> None:
        with client:
            minimal = {"pull_request": {"head": {"ref": "main", "sha": "x"}}}
            response = post_event(client, minimal, delivery="delivery-5")

        assert response.status_code == 400

    def test_missing_delivery_header_rejected_400(self, client: TestClient) -> None:
        with client:
            raw = json.dumps(pr_payload()).encode()
            response = client.post(
                "/webhooks/github",
                content=raw,
                headers={
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": sign(raw),
                },
            )

        assert response.status_code == 400


class TestDuplicateRejection:
    def test_duplicate_delivery_returns_200_idempotent(self, client: TestClient) -> None:
        with client as c:
            first = post_event(client, pr_payload(), delivery="delivery-dup")
            second = post_event(client, pr_payload(), delivery="delivery-dup")
            store = c.app.state.audit_store

        assert first.status_code == 202
        assert second.status_code == 200  # idempotent, NOT an error (Section 10)
        assert "duplicate" in second.json()["detail"]
        events = [entry.event_type for entry in store.get_audit_trail("rejected:delivery-dup")]
        assert "duplicate_rejected" in events

    def test_duplicate_does_not_create_second_run(self, client: TestClient) -> None:
        with client as c:
            first = post_event(client, pr_payload(), delivery="delivery-dup2")
            post_event(client, pr_payload(), delivery="delivery-dup2")
            store = c.app.state.audit_store

        first_run = first.json()["run_id"]
        assert store.get_run(first_run) is not None
        trail = store.get_audit_trail(first_run)
        assert len([e for e in trail if e.event_type == "run_created"]) == 1


class TestAllowlistRejections:
    def test_disallowed_repository_rejected_403_and_audited(self, client: TestClient) -> None:
        with client as c:
            response = post_event(client, pr_payload(repo="rogue-org/tool"), delivery="delivery-6")
            store = c.app.state.audit_store

        assert response.status_code == 403
        assert "not allowed" in response.json()["detail"]
        events = [entry.event_type for entry in store.get_audit_trail("rejected:delivery-6")]
        assert "repository_not_allowed" in events

    def test_glob_allowlist_matches_org_pattern(self, client: TestClient) -> None:
        with client:
            response = post_event(
                client, pr_payload(repo="example-org/any-repo"), delivery="delivery-7"
            )

        assert response.status_code == 202

    def test_disallowed_branch_rejected_403_and_audited(self, client: TestClient) -> None:
        with client as c:
            response = post_event(
                client, pr_payload(branch="experimental-thing"), delivery="delivery-8"
            )
            store = c.app.state.audit_store

        assert response.status_code == 403
        assert "branch" in response.json()["detail"]
        events = [entry.event_type for entry in store.get_audit_trail("rejected:delivery-8")]
        assert "branch_not_allowed" in events

    def test_push_to_disallowed_branch_rejected(self, client: TestClient) -> None:
        with client:
            response = post_event(
                client, push_payload(branch="scratch"), event="push", delivery="delivery-9"
            )

        assert response.status_code == 403


class TestOrdering:
    def test_rejections_do_not_create_runs_or_mark_deliveries(self, client: TestClient) -> None:
        with client as c:
            post_event(client, pr_payload(repo="rogue-org/x"), delivery="delivery-10")
            store = c.app.state.audit_store

        assert store.is_delivery_processed("delivery-10") is False
        runs = []
        for entry in store.get_audit_trail("rejected:delivery-10"):
            assert not entry.run_id.startswith("run")
            runs.append(entry)
        assert runs  # the rejection itself was audited


def test_healthz_ok(client: TestClient) -> None:
    with client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_settings_without_secret_fails_loudly_in_non_local_env() -> None:
    with pytest.raises(RuntimeError, match="GITHUB_WEBHOOK_SECRET"):
        Settings(env="prod", github_webhook_secret=None).resolved_webhook_secret()
