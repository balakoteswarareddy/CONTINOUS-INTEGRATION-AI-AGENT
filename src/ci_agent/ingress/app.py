"""FastAPI application for the CI Agent control plane (Batches 2-5).

One app, five concern families mounted as routers:

* ``/webhooks/github`` — ingress/trigger gateway + Execution Observer events
  (Batch 2 + Batch 4);
* ``/admin/*`` — project onboarding + pipeline spec registration (Batch 5);
* ``/runs/{id}/approve|reject`` — human approval API (Batch 5);
* ``/runs/{id}``, ``/runs/{id}/report`` — reporting views (Batch 5);
* ``/healthz`` — ops liveness.

All wiring (settings, stores, orchestrator, reliability guards) happens in
:func:`create_app` so tests can build isolated instances; the module-level
``app`` is what uvicorn boots (``uvicorn ci_agent.ingress.app:app``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from ci_agent.adapters.github_actions.adapter import GitHubActionsAdapter
from ci_agent.adapters.github_actions.client import GitHubAuthConfig, GitHubClient
from ci_agent.audit.audit_store import AuditStore
from ci_agent.config.settings import Settings, get_settings
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.governance import load_intake_schema, load_policy_file, load_policy_spec
from ci_agent.ingress import github_webhook
from ci_agent.ingress.replay_guard import ReplayGuard
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.observer.github_events import ObserverEventHandlers
from ci_agent.orchestrator.approval_api import router as approval_api_router
from ci_agent.orchestrator.phase_a_orchestrator import PhaseAOrchestrator
from ci_agent.planner.planner import Planner
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.policy.opa_client import OPAClient
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.projects.admin_api import router as admin_api_router
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.circuit_breaker import CircuitBreaker
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard
from ci_agent.reporting.evidence_assembler import EvidenceAssembler
from ci_agent.reporting.report_api import router as report_api_router


def _load_allowlists() -> tuple[list[str], list[str]]:
    """Load repository/branch glob allowlists from the governed identity policy."""
    policy = load_policy_file("identity_policy")
    return policy.get("allowed_repositories", []), policy.get("allowed_branches", [])


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the control-plane FastAPI app.

    Constructing the app resolves the webhook secret and (outside ``local``)
    the admin key immediately — missing secrets fail loudly at startup.
    """
    resolved_settings = settings or get_settings()
    webhook_secret = resolved_settings.resolved_webhook_secret()
    admin_api_key = resolved_settings.resolved_admin_api_key()
    allowed_repositories, allowed_branches = _load_allowlists()

    engine = create_engine(resolved_settings.database_url)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    replay_guard = ReplayGuard(audit_store)
    observer = ExecutionObserver(session_factory, audit_store)
    observer_events = ObserverEventHandlers(observer, audit_store, session_factory)

    # --- Batch 5: registry, planner, PDP, orchestrator, reliability ----------
    project_registry = ProjectRegistry(session_factory)
    intake_schema = load_intake_schema()
    policy_spec = load_policy_spec()
    planner = Planner(TemplateRegistry(), policy_spec)
    opa_client = OPAClient(resolved_settings.opa_url, resolved_settings.opa_timeout_seconds)
    pdp = PolicyDecisionPoint(opa_client, audit_store, policy_spec, session_factory=session_factory)
    github_auth = GitHubAuthConfig(
        pat=resolved_settings.github_pat,
        app_id=resolved_settings.github_app_id,
        private_key_path=resolved_settings.github_app_private_key_path,
        installation_id=resolved_settings.github_installation_id,
    )
    github_client = GitHubClient(github_auth)
    adapter = GitHubActionsAdapter(github_client)
    concurrency_guard = ConcurrencyGuard(resolved_settings.max_concurrent_runs_per_project)
    orchestrator = PhaseAOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=project_registry,
        planner=planner,
        pdp=pdp,
        adapter=adapter,
        github_client=github_client,
        concurrency_guard=concurrency_guard,
        policy_spec_version=policy_spec.policy_version,
    )
    observer_events.on_stage_transition = orchestrator.on_stage_transition
    evidence_assembler = EvidenceAssembler(session_factory, audit_store)

    # Breakers guard the two external dependencies (Section 11). Open OPA
    # breaker -> OPAUnavailableError -> documented PDP fail-closed behaviour.
    opa_breaker = CircuitBreaker("opa", failure_threshold=5, recovery_timeout_seconds=30.0)
    github_breaker = CircuitBreaker("github", failure_threshold=8, recovery_timeout_seconds=60.0)

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
        title="CI Agent — Control Plane",
        version="0.2.0",
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.webhook_secret = webhook_secret
    application.state.admin_api_key = admin_api_key
    application.state.audit_store = audit_store
    application.state.replay_guard = replay_guard
    application.state.observer = observer
    application.state.observer_events = observer_events
    application.state.allowed_repositories = allowed_repositories
    application.state.allowed_branches = allowed_branches
    application.state.session_factory = session_factory
    application.state.project_registry = project_registry
    application.state.intake_schema = intake_schema
    application.state.pdp = pdp
    application.state.orchestrator = orchestrator
    application.state.evidence_assembler = evidence_assembler
    application.state.opa_breaker = opa_breaker
    application.state.github_breaker = github_breaker
    application.state.concurrency_guard = concurrency_guard

    application.include_router(github_webhook.router)
    application.include_router(admin_api_router)
    application.include_router(approval_api_router)
    application.include_router(report_api_router)

    @application.get("/healthz")
    async def healthz(request: Request) -> dict[str, str]:
        """Liveness probe for later ops use (Batch 2 guardrail)."""
        _ = request  # unused; keeps signature explicit for typing
        return {"status": "ok"}

    return application


# Module-level app instance used by `uvicorn ci_agent.ingress.app:app`.
app = create_app()
