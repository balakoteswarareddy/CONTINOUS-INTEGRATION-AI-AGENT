"""FastAPI application for the Ingress / Trigger Gateway (Batch 2, Task B).

Minimal by design: exactly one webhook endpoint plus ``/healthz`` for ops.
All application wiring (settings, webhook secret, audit store, governance
allowlists) happens in :func:`create_app` so tests can build isolated
instances; the module-level ``app`` is what uvicorn boots
(``uvicorn ci_agent.ingress.app:app``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from ci_agent.audit.audit_store import AuditStore
from ci_agent.config.settings import Settings, get_settings
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.governance import load_policy_file
from ci_agent.ingress import github_webhook
from ci_agent.ingress.replay_guard import ReplayGuard


def _load_allowlists() -> tuple[list[str], list[str]]:
    """Load repository/branch glob allowlists from the governed identity policy."""
    policy = load_policy_file("identity_policy")
    return policy.get("allowed_repositories", []), policy.get("allowed_branches", [])


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ingress FastAPI app.

    Constructing the app resolves the webhook secret immediately — an unset
    ``GITHUB_WEBHOOK_SECRET`` in a non-local environment fails loudly here, at
    startup, per Batch 2 Task B step 2.
    """
    resolved_settings = settings or get_settings()
    webhook_secret = resolved_settings.resolved_webhook_secret()
    allowed_repositories, allowed_branches = _load_allowlists()

    engine = create_engine(resolved_settings.database_url)
    audit_store = AuditStore(get_session_factory(engine))
    replay_guard = ReplayGuard(audit_store)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        # Local/dev convenience: create tables so a fresh checkout boots
        # without running Alembic first. Real deployments migrate with
        # `alembic upgrade head` (documented in README/NOTES.md).
        if resolved_settings.env == "local":
            Base.metadata.create_all(engine)
        yield
        engine.dispose()

    application = FastAPI(
        title="CI Agent — Ingress / Trigger Gateway",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.webhook_secret = webhook_secret
    application.state.audit_store = audit_store
    application.state.replay_guard = replay_guard
    application.state.allowed_repositories = allowed_repositories
    application.state.allowed_branches = allowed_branches

    application.include_router(github_webhook.router)

    @application.get("/healthz")
    async def healthz(request: Request) -> dict[str, str]:
        """Liveness probe for later ops use (Batch 2 guardrail)."""
        _ = request  # unused; keeps signature explicit for typing
        return {"status": "ok"}

    return application


# Module-level app instance used by `uvicorn ci_agent.ingress.app:app`.
app = create_app()
