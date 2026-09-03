"""Batch 5.1 Item 2: identity policy deny-by-default split + local-dev override.

The committed ``identity_policy.yaml`` must stay EMPTY (deny everything).
The permissive allowlist lives ONLY in the clearly-named local-dev example
file, which the app loads exclusively for ``CI_AGENT_ENV=local`` — loudly.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.governance import (
    load_identity_policy,
    load_policy_spec,
)


def test_committed_identity_policy_is_deny_by_default() -> None:
    """Regression guard: the SHIPPED policy file must never carry allowlists."""
    committed = load_identity_policy(local_dev_override=False)
    assert committed["allowed_repositories"] == []
    assert committed["allowed_branches"] == []


def test_local_dev_override_file_is_separate_and_permissive() -> None:
    override = load_identity_policy(local_dev_override=True)
    assert override["allowed_repositories"] == ["example-org/*"]
    assert "main" in override["allowed_branches"]
    # It is a different file, not the committed one mutated.
    assert load_identity_policy(local_dev_override=False)["allowed_repositories"] == []


def test_policy_spec_override_only_swaps_identity() -> None:
    default_spec = load_policy_spec()
    override_spec = load_policy_spec(local_dev_override=True)
    assert default_spec.identity_policy.allowed_repositories == []
    assert override_spec.identity_policy.allowed_repositories == ["example-org/*"]
    # Every other family is untouched by the override.
    assert override_spec.tool_policy == default_spec.tool_policy
    assert override_spec.security_policy == default_spec.security_policy
    assert override_spec.approval_policy == default_spec.approval_policy
    assert override_spec.policy_version == default_spec.policy_version


def test_local_app_uses_override_and_logs_loud_warning(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    """CI_AGENT_ENV=local -> override active AND the warning is impossible to miss."""
    from ci_agent.ingress.app import create_app

    settings = Settings(env="local", database_url=f"sqlite:///{tmp_path / 'local.db'}")
    with caplog.at_level(logging.WARNING, logger="ci_agent.ingress"):
        application = create_app(settings)
    assert any(
        "LOCAL-DEV identity policy override" in record.message
        and "do not use in shared/prod" in record.message
        for record in caplog.records
    ), [record.message for record in caplog.records]
    assert application.state.allowed_repositories == ["example-org/*"]


def test_non_local_app_does_not_log_override_warning(
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    from ci_agent.ingress.app import create_app

    settings = Settings(
        env="dev",
        database_url=f"sqlite:///{tmp_path / 'dev.db'}",
        github_webhook_secret="x" * 8,
        admin_api_key="k" * 8,
    )
    with caplog.at_level(logging.WARNING, logger="ci_agent.ingress"):
        application = create_app(settings)
    assert not any(
        "LOCAL-DEV identity policy override" in record.message for record in caplog.records
    )
    assert application.state.allowed_repositories == []


def _signed_webhook(client: TestClient, repository: str, delivery: str):
    import hashlib
    import hmac as hmac_mod
    import json

    secret = client.app.state.settings.resolved_webhook_secret()
    payload = json.dumps(
        {
            "action": "opened",
            "pull_request": {"head": {"sha": "cafe1234", "ref": "main"}},
            "repository": {"full_name": repository},
        }
    ).encode()
    signature = "sha256=" + hmac_mod.new(secret, payload, hashlib.sha256).hexdigest()
    return client.post(
        "/webhooks/github",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": signature,
        },
    )


def test_dev_mode_default_rejects_every_repository(tmp_path) -> None:
    """DoD: dev/prod with the committed empty default rejects ALL repositories."""
    from ci_agent.db.base import Base, create_engine
    from ci_agent.ingress.app import create_app

    # dev mode does not auto-create tables (local-only convenience): prepare
    # the file DB explicitly, as a real deployment would via Alembic.
    database_path = tmp_path / "dev.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    engine.dispose()

    settings = Settings(
        env="dev",
        database_url=f"sqlite:///{database_path}",
        github_webhook_secret="x" * 8,
        admin_api_key="k" * 8,
    )
    application = create_app(settings)
    with TestClient(application) as client:
        response = _signed_webhook(client, "example-org/payments-api", "d-denied-1")
    assert response.status_code == 403
    assert "not allowed" in response.json()["detail"]


def test_local_mode_accepts_override_allowlisted_repository(tmp_path) -> None:
    """Same request, local env: the override allowlist admits example-org/*."""
    from ci_agent.ingress.app import create_app

    settings = Settings(env="local", database_url=f"sqlite:///{tmp_path / 'local.db'}")
    application = create_app(settings)
    with TestClient(application) as client:
        accepted = _signed_webhook(client, "example-org/payments-api", "d-local-1")
        rejected = _signed_webhook(client, "rogue-org/tool", "d-local-2")
    assert accepted.status_code == 202
    assert rejected.status_code == 403  # override is scoped, not allow-all
