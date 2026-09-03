"""FastAPI application for the CI Agent control plane (Batches 2-5).

One app, six concern families mounted as routers:

* ``/webhooks/github`` — ingress/trigger gateway + Execution Observer events
  (Batch 2 + Batch 4);
* ``/webhooks/gitlab`` — Execution Observer events for GitLab pipelines/jobs
  (Batch 8; token-authenticated, replay-guarded, run creation stays GitHub-side);
* ``/admin/*`` — project onboarding + pipeline spec registration (Batch 5);
* ``/runs/{id}/approve|reject`` — human approval API (Batch 5);
* ``/runs/{id}``, ``/runs/{id}/report`` — reporting views (Batch 5);
* ``/healthz`` — ops liveness.

All wiring (settings, stores, orchestrator, reliability guards) happens in
:func:`create_app` so tests can build isolated instances; the module-level
``app`` is what uvicorn boots (``uvicorn ci_agent.ingress.app:app``).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from ci_agent.adapters.base import DispatchRef
from ci_agent.adapters.github_actions.adapter import GitHubActionsAdapter
from ci_agent.adapters.github_actions.client import GitHubAuthConfig, GitHubClient
from ci_agent.adapters.github_actions.compiler import REPORT_UPLOAD_STAGES
from ci_agent.adapters.gitlab_ci.adapter import GitLabCIAdapter
from ci_agent.adapters.gitlab_ci.client import GitLabClient
from ci_agent.adapters.jenkins.adapter import JenkinsAdapter
from ci_agent.adapters.jenkins.client import JenkinsClient
from ci_agent.adapters.router import AdapterRouter
from ci_agent.ai.features.failure_triage import FailureTriage
from ci_agent.ai.features.pipeline_explainer import PipelineExplainer
from ci_agent.ai.features.report_summarizer import ReportSummarizer
from ci_agent.ai.features.requirement_normalizer import RequirementNormalizer
from ci_agent.ai.gateway.provider_registry import build_gateway
from ci_agent.audit.audit_store import AuditStore
from ci_agent.config.settings import Settings, get_settings
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.db.models import RunRecord
from ci_agent.exceptions.exception_api import router as exception_api_router
from ci_agent.exceptions.exception_service import ExceptionService
from ci_agent.governance import (
    load_identity_policy,
    load_intake_schema,
    load_policy_spec,
)
from ci_agent.ingress import github_webhook, gitlab_webhook
from ci_agent.ingress.ai_api import router as ai_api_router
from ci_agent.ingress.replay_guard import ReplayGuard
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.observer.github_events import ObserverEventHandlers
from ci_agent.observer.gitlab_events import GitLabEventHandlers
from ci_agent.orchestrator.approval_api import router as approval_api_router
from ci_agent.orchestrator.phase_a_orchestrator import PhaseAOrchestrator
from ci_agent.orchestrator.phase_b_orchestrator import PhaseBOrchestrator
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
from ci_agent.security.security_evidence_service import SecurityEvidenceService
from ci_agent.supplychain.sbom_service import SBOMService
from ci_agent.supplychain.signing_service import SigningService, VerifyRunner
from ci_agent.telemetry.emitter import TelemetryEmitter

LOGGER = logging.getLogger("ci_agent.ingress")

# Batch 5.1 (Item 2): the committed identity policy denies everything; ONLY
# the `local` environment may swap in the clearly-marked local-dev override.
LOCAL_DEV_ENV = "local"


def _load_allowlists(settings: Settings) -> tuple[list[str], list[str]]:
    """Load repository/branch allowlists per environment (fail-closed default).

    ``local``: the examples/identity_policy.local-dev.yaml override, loudly
    logged. Every other environment: the committed deny-everything default.
    """
    if settings.env == LOCAL_DEV_ENV:
        policy = load_identity_policy(local_dev_override=True)
        LOGGER.warning(
            "⚠ Using LOCAL-DEV identity policy override "
            "(examples/identity_policy.local-dev.yaml) — do not use in "
            "shared/prod environments. Committed default remains "
            "deny-everything."
        )
    else:
        policy = load_identity_policy(local_dev_override=False)
    return (
        list(policy.get("allowed_repositories", [])),
        list(policy.get("allowed_branches", [])),
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the control-plane FastAPI app.

    Constructing the app resolves the webhook secret and (outside ``local``)
    the admin key immediately — missing secrets fail loudly at startup.
    """
    resolved_settings = settings or get_settings()
    webhook_secret = resolved_settings.resolved_webhook_secret()
    admin_api_key = resolved_settings.resolved_admin_api_key()
    allowed_repositories, allowed_branches = _load_allowlists(resolved_settings)

    engine = create_engine(resolved_settings.database_url)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    replay_guard = ReplayGuard(audit_store)
    # Batch 8, Task E: the singleton telemetry emitter (never raises; its
    # logger can be re-configured by deployment tooling without code change).
    telemetry_emitter = TelemetryEmitter()
    observer = ExecutionObserver(session_factory, audit_store, telemetry_emitter=telemetry_emitter)
    observer_events = ObserverEventHandlers(observer, audit_store, session_factory)
    # Batch 8, Task A: GitLab pipeline/job handlers (same wiring pattern).
    gitlab_observer_events = GitLabEventHandlers(observer, audit_store, session_factory)

    # --- Batch 5: registry, planner, PDP, orchestrator, reliability ----------
    project_registry = ProjectRegistry(session_factory)
    intake_schema = load_intake_schema()
    policy_spec = load_policy_spec(local_dev_override=(resolved_settings.env == LOCAL_DEV_ENV))
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
    # --- Batch 8, Task C: the AdapterRouter (multi-runner wiring) ------------
    # GitHub registers unconditionally (existing behaviour: credentials fail
    # at request time, not construction). GitLab/Jenkins register when their
    # credentials are configured — and ALWAYS in local (documented dev
    # placeholders). In dev/prod WITHOUT credentials the adapter is simply
    # absent: a project routed to it fails LOUDLY at plan time with
    # UnknownRunnerError (fail closed; never a silent fallback). Documented
    # deviation from a literal "startup fails without the token" reading —
    # see NOTES.md.
    adapter_router = AdapterRouter(default_runner=resolved_settings.default_runner)
    adapter_router.register("github_actions", GitHubActionsAdapter(github_client))
    if resolved_settings.gitlab_access_token or resolved_settings.env == LOCAL_DEV_ENV:
        gitlab_client = GitLabClient(resolved_settings.resolved_gitlab_access_token())
        adapter_router.register("gitlab_ci", GitLabCIAdapter(gitlab_client))
    else:
        LOGGER.info("gitlab_ci adapter not registered (GITLAB_ACCESS_TOKEN unset)")
    if resolved_settings.jenkins_configured() or resolved_settings.env == LOCAL_DEV_ENV:
        jenkins_url, jenkins_user, jenkins_token = resolved_settings.resolved_jenkins_config()
        adapter_router.register(
            "jenkins", JenkinsAdapter(JenkinsClient(jenkins_url, jenkins_user, jenkins_token))
        )
    else:
        LOGGER.info("jenkins adapter not registered (JENKINS_* variables unset)")
    adapter = adapter_router  # the orchestrators accept router or adapter
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
        require_human_approval_for=frozenset(
            policy_spec.approval_policy.require_human_approval_for
        ),
        telemetry_emitter=telemetry_emitter,
    )
    observer_events.on_stage_transition = orchestrator.on_stage_transition
    gitlab_observer_events.on_stage_transition = orchestrator.on_stage_transition
    evidence_assembler = EvidenceAssembler(session_factory, audit_store)

    # --- Batch 6: real security findings pipeline ----------------------------
    security_evidence = SecurityEvidenceService(session_factory, audit_store)
    gha_adapter = GitHubActionsAdapter(github_client)

    def _collect_scan_evidence(run_id: str, stage_id: str) -> None:
        """Fetch a scan stage's raw report artifact and collect findings.

        Called by the observer BEFORE a scan stage is marked terminal (so the
        policy gate never runs without evidence). The RunRecord must already
        carry dispatch coordinates (the orchestrator sets them at dispatch).
        Missing artifact / parse failure => ParserWarning flagged by the
        service; the PDP then fails closed on the flagged condition.
        """
        with session_factory() as session:
            run = session.get(RunRecord, run_id)
            if run is None or not run.dispatch_branch or not run.external_run_id:
                return  # nothing dispatched yet; nothing to fetch
            dispatch_ref = DispatchRef(
                run_id=run_id,
                repository=run.repository,
                branch=run.dispatch_branch,
                external_run_id=run.external_run_id,
            )
        tool_by_file = REPORT_UPLOAD_STAGES.get(stage_id, {})
        try:
            contents = gha_adapter.download_stage_scan_artifact(dispatch_ref, stage_id)
        except Exception as exc:
            # Download failure (auth, transport, rate limit): record a
            # ParserWarning incident so the policy gate fails closed instead
            # of silently treating the stage as clean. Never raise past the
            # observer — the anomaly is captured as evidence.
            LOGGER.warning(
                "scan artifact download failed for run=%s stage=%s: %s",
                run_id,
                stage_id,
                exc,
            )
            security_evidence.collect_findings(
                run_id, stage_id, next(iter(tool_by_file.values()), stage_id), ""
            )
            return
        if not contents:
            # Artifact absent: flagged as an incident (not a clean scan).
            security_evidence.collect_findings(
                run_id, stage_id, next(iter(tool_by_file.values()), stage_id), ""
            )
            return
        for filename, tool in tool_by_file.items():
            security_evidence.collect_findings(run_id, stage_id, tool, contents.get(filename, ""))

    observer.scan_evidence_collector = _collect_scan_evidence

    # --- Batch 7: supply-chain services + Phase B orchestrator ---------------
    exception_service = ExceptionService(session_factory, audit_store)
    sbom_service = SBOMService(session_factory, audit_store)
    signing_service = SigningService(
        session_factory,
        audit_store,
        sbom_service,
        verify_runner=VerifyRunner(resolved_settings.cosign_binary),
    )

    def _download_phase_b_evidence(run_id: str, stage_id: str) -> dict[str, str]:
        """Fetch a Phase B stage's uploaded evidence files (digest/SBOM/sig)."""
        with session_factory() as session:
            run = session.get(RunRecord, run_id)
            if run is None or not run.phase_b_branch or not run.phase_b_external_run_id:
                return {}
            dispatch_ref = DispatchRef(
                run_id=run_id,
                repository=run.repository,
                branch=run.phase_b_branch,
                external_run_id=run.phase_b_external_run_id,
            )
        try:
            return gha_adapter.download_stage_scan_artifact(dispatch_ref, stage_id)
        except Exception as exc:  # fail closed upstream: collector raises
            LOGGER.warning(
                "phase B evidence download failed for run=%s stage=%s: %s",
                run_id,
                stage_id,
                exc,
            )
            return {}

    phase_b_orchestrator = PhaseBOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=project_registry,
        planner=planner,
        pdp=pdp,
        adapter=adapter,
        github_client=github_client,
        concurrency_guard=concurrency_guard,
        policy_spec_version=policy_spec.policy_version,
        sbom_service=sbom_service,
        signing_service=signing_service,
        exception_service=exception_service,
        evidence_downloader=_download_phase_b_evidence,
        telemetry_emitter=telemetry_emitter,
    )
    # Section 5.2: an APPROVED Phase A merge decision is the ONLY Phase B
    # trigger — the enforcement lives in PhaseBOrchestrator.start itself.
    orchestrator.on_phase_a_approved = phase_b_orchestrator.start

    # Breakers guard the two external dependencies (Section 11). Open OPA
    # breaker -> OPAUnavailableError -> documented PDP fail-closed behaviour.
    opa_breaker = CircuitBreaker("opa", failure_threshold=5, recovery_timeout_seconds=30.0)
    github_breaker = CircuitBreaker("github", failure_threshold=8, recovery_timeout_seconds=60.0)

    # --- Batch 9 (Section 13 Phase 4): the AI model gateway + features -----
    # Breaker-wrapped, NoopProvider-fallback gateway. The committed ai_policy
    # is deny-by-default (allowed_model_providers: [], allowed_data_
    # classification: [public]), so with no governed policy change the
    # gateway answers via the deterministic no-model fallback — the platform
    # is fully functional before any provider is configured (Section 18).
    # AI_PROVIDER defaults to noop (safe default; no model without explicit
    # configuration).
    ai_breaker = CircuitBreaker("model_gateway", failure_threshold=3, recovery_timeout_seconds=60.0)
    model_gateway = build_gateway(
        ai_policy=policy_spec.ai_policy,
        session_factory=session_factory,
        provider_setting=resolved_settings.resolved_ai_provider(),
        token_budget=resolved_settings.model_token_budget,
        breaker=ai_breaker,
    )
    failure_triage = FailureTriage(model_gateway)
    report_summarizer = ReportSummarizer(model_gateway)
    pipeline_explainer = PipelineExplainer(model_gateway)
    requirement_normalizer = RequirementNormalizer(model_gateway)

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
    application.state.gitlab_observer_events = gitlab_observer_events
    # Batch 8: shared-secret for POST /webhooks/gitlab (None in non-local
    # environments without GITLAB_WEBHOOK_TOKEN -> endpoint fail-closed 401).
    application.state.gitlab_webhook_token = resolved_settings.resolved_gitlab_webhook_token()
    application.state.telemetry_emitter = telemetry_emitter
    application.state.adapter_router = adapter_router
    application.state.allowed_repositories = allowed_repositories
    application.state.allowed_branches = allowed_branches
    application.state.session_factory = session_factory
    application.state.project_registry = project_registry
    application.state.intake_schema = intake_schema
    application.state.pdp = pdp
    application.state.orchestrator = orchestrator
    application.state.evidence_assembler = evidence_assembler
    application.state.security_evidence = security_evidence
    application.state.exception_service = exception_service
    application.state.sbom_service = sbom_service
    application.state.signing_service = signing_service
    application.state.phase_b_orchestrator = phase_b_orchestrator
    application.state.opa_breaker = opa_breaker
    application.state.github_breaker = github_breaker
    application.state.concurrency_guard = concurrency_guard
    # Batch 9: AI gateway + features (advisory only; see ai/ package docs).
    application.state.ai_breaker = ai_breaker
    application.state.model_gateway = model_gateway
    application.state.failure_triage = failure_triage
    application.state.report_summarizer = report_summarizer
    application.state.pipeline_explainer = pipeline_explainer
    application.state.requirement_normalizer = requirement_normalizer

    application.include_router(github_webhook.router)
    application.include_router(gitlab_webhook.router)
    application.include_router(admin_api_router)
    application.include_router(approval_api_router)
    application.include_router(report_api_router)
    application.include_router(exception_api_router)
    application.include_router(ai_api_router)

    @application.get("/healthz")
    async def healthz(request: Request) -> dict[str, str]:
        """Liveness probe for later ops use (Batch 2 guardrail)."""
        _ = request  # unused; keeps signature explicit for typing
        return {"status": "ok"}

    return application


# Module-level app instance used by `uvicorn ci_agent.ingress.app:app`.
app = create_app()
