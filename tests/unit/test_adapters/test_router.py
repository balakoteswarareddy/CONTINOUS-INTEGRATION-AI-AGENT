"""AdapterRouter tests (Batch 8, Task C)."""

from __future__ import annotations

import pytest

from ci_agent.adapters.base import CompiledArtifact, DispatchRef, RunnerAdapter
from ci_agent.adapters.errors import UnknownRunnerError
from ci_agent.adapters.router import AdapterRouter, select_runner_name
from ci_agent.core.models.execution_plan import ExecutionPlan


class _StubAdapter(RunnerAdapter):
    """Minimal concrete adapter for routing tests."""

    def __init__(self, name: str) -> None:
        self.name = name

    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
        raise NotImplementedError

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        raise NotImplementedError

    def poll_status(self, dispatch_ref: DispatchRef) -> object:
        raise NotImplementedError

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        raise NotImplementedError


class TestGetAdapter:
    def test_returns_the_registered_adapter(self) -> None:
        github = _StubAdapter("github")
        router = AdapterRouter({"github_actions": github})
        assert router.get_adapter("github_actions") is github

    def test_unknown_runner_raises_never_falls_back(self) -> None:
        router = AdapterRouter(
            {"github_actions": _StubAdapter("github")}, default_runner="github_actions"
        )
        with pytest.raises(UnknownRunnerError, match="gitlab_ci"):
            router.get_adapter("gitlab_ci")

    def test_error_message_lists_known_runners(self) -> None:
        router = AdapterRouter({"github_actions": _StubAdapter("g")})
        with pytest.raises(UnknownRunnerError, match="github_actions"):
            router.get_adapter("nope")

    def test_empty_router_raises_for_any_runner(self) -> None:
        router = AdapterRouter()
        with pytest.raises(UnknownRunnerError):
            router.get_adapter("github_actions")


class TestAdapterForProfile:
    def test_default_runner_used_when_profile_runner_is_an_os_string(self) -> None:
        """ProjectProfile.runner carries the runner OS today (linux/windows/
        macos) — the deployment default selects the platform (NOTES.md)."""
        github = _StubAdapter("github")
        router = AdapterRouter({"github_actions": github}, default_runner="github_actions")
        assert router.adapter_for_profile("linux") is github
        assert router.adapter_for_profile(None) is github

    def test_profile_runner_wins_when_it_is_a_registered_platform(self) -> None:
        github = _StubAdapter("github")
        gitlab = _StubAdapter("gitlab")
        router = AdapterRouter(
            {"github_actions": github, "gitlab_ci": gitlab}, default_runner="github_actions"
        )
        assert router.adapter_for_profile("gitlab_ci") is gitlab

    def test_missing_default_registration_fails_loudly(self) -> None:
        """No silent fallback: a misconfigured default raises at plan time."""
        router = AdapterRouter(
            {"gitlab_ci": _StubAdapter("gitlab")}, default_runner="github_actions"
        )
        with pytest.raises(UnknownRunnerError, match="github_actions"):
            router.adapter_for_profile("linux")


class TestRouterMisc:
    def test_register_adds_and_replaces(self) -> None:
        router = AdapterRouter()
        assert router.known_runners == []
        first = _StubAdapter("one")
        second = _StubAdapter("two")
        router.register("github_actions", first)
        assert router.get_adapter("github_actions") is first
        router.register("github_actions", second)
        assert router.get_adapter("github_actions") is second

    def test_select_runner_name_extracts_the_profile_field(self) -> None:
        class _Profile:
            runner = "linux"

        class _Empty:
            pass

        assert select_runner_name(_Profile()) == "linux"
        assert select_runner_name(_Empty()) is None
        assert select_runner_name(None) is None

    def test_repr_lists_runners(self) -> None:
        router = AdapterRouter({"github_actions": _StubAdapter("g")})
        assert "github_actions" in repr(router)


class TestProviderMatrixAlignment:
    def test_router_vocabulary_matches_provider_matrix(self) -> None:
        """The router keys use exactly the provider_matrix runner names."""
        from ci_agent.governance import loader

        matrix = loader.load_provider_matrix()
        assert set(matrix["runner_providers"]) == {"github_actions", "gitlab_ci", "jenkins"}


class TestOrchestratorErrorParking:
    """Batch 8 acceptance: an unknown runner fails LOUDLY and parks the run.

    The router is mocked (``MagicMock(spec=AdapterRouter)`` so the
    orchestrator's isinstance dispatch takes the router branch) and raises
    the real :class:`UnknownRunnerError`; the orchestrator's generic
    error-parking path must then (a) park the run in ERROR, (b) audit the
    failure, and (c) never dispatch. All external dependencies are fakes —
    no live OPA, no credentials.
    """

    def test_unknown_runner_parks_run_in_error(self, tmp_path) -> None:
        from unittest.mock import MagicMock

        from tests.unit.test_orchestrator.test_phase_b_orchestrator import (
            REPO,
            _phase_b_spec_document,
        )
        from tests.unit.test_projects.test_project_registry import INTAKE_SCHEMA, _answers

        from ci_agent.audit.audit_store import AuditStore
        from ci_agent.core.models.common import PolicyDecision
        from ci_agent.db.base import Base, create_engine, get_session_factory
        from ci_agent.db.models import RunRecord
        from ci_agent.governance import load_policy_spec
        from ci_agent.orchestrator.phase_a_orchestrator import (
            OrchestrationError,
            PhaseAOrchestrator,
        )
        from ci_agent.planner.planner import Planner
        from ci_agent.planner.templates.template_registry import TemplateRegistry
        from ci_agent.policy.models import PolicyDecisionResult
        from ci_agent.projects.project_registry import ProjectRegistry
        from ci_agent.reliability.concurrency_guard import ConcurrencyGuard

        engine = create_engine(f"sqlite:///{tmp_path / 'router-error.db'}")
        Base.metadata.create_all(engine)
        session_factory = get_session_factory(engine)
        audit_store = AuditStore(session_factory)
        registry = ProjectRegistry(session_factory)
        registry.register_project(
            intake_answers=_answers(), intake_schema=INTAKE_SCHEMA, repository=REPO
        )
        registry.register_pipeline_spec(REPO, _phase_b_spec_document())

        # The mocked router: a spec'd mock passes the orchestrator's
        # isinstance(AdapterRouter) check and raises the REAL error type the
        # router raises for an unregistered runner.
        router = MagicMock(spec=AdapterRouter)
        router.adapter_for_profile.side_effect = UnknownRunnerError(
            "no adapter registered for runner 'gitlab_ci'; known runners: github_actions"
        )

        class _FakePDP:
            def evaluate_gate(self, stage_id: str, facts: object) -> PolicyDecisionResult:
                return PolicyDecisionResult(
                    decision=PolicyDecision.PASS,
                    policy_family="aggregated",
                    policy_version="1.0.0",
                )

        guard = ConcurrencyGuard(3)
        orchestrator = PhaseAOrchestrator(
            audit_store=audit_store,
            session_factory=session_factory,
            project_registry=registry,
            planner=Planner(TemplateRegistry(), load_policy_spec()),
            pdp=_FakePDP(),  # type: ignore[arg-type]
            adapter=router,
            github_client=MagicMock(),
            concurrency_guard=guard,
            policy_spec_version="1.0.0",
        )
        audit_store.create_run(
            run_id="run-unknown-runner",
            project_id=REPO,
            repository=REPO,
            trigger_type="push",
            source_sha="cafe1234",
        )

        # advance() wraps the router's raise: the run parks in ERROR and the
        # caller sees OrchestrationError carrying the router's message (the
        # class name lands in the audited detail below — fail closed, never a
        # silent default).
        with pytest.raises(OrchestrationError, match="no adapter registered for runner"):
            orchestrator.advance("run-unknown-runner", {"type": "run_created"})

        # (a) the run is parked in ERROR, with no dispatch coordinates (c).
        with session_factory() as session:
            run = session.get(RunRecord, "run-unknown-runner")
            assert run is not None
            assert run.current_state == "error"
            assert run.dispatch_branch is None
            assert run.external_run_id is None

        # (b) the generic error-parking path audited the failure.
        trail = audit_store.get_audit_trail("run-unknown-runner")
        parking = [e for e in trail if e.event_type == "orchestration_error"]
        assert parking, "error parking must be audited"
        assert any("UnknownRunnerError" in (e.payload_json or "") for e in parking)

        # (c) no dispatch: the router was consulted exactly once and never
        # produced an adapter, so no compile/dispatch could happen through it.
        router.adapter_for_profile.assert_called_once()

        # The concurrency quota slot acquired just before dispatch was
        # released on the failure path — no quota leak.
        assert guard.in_flight(REPO) == 0
