"""Telemetry wiring tests (Batch 8, Task E).

Proves the emitter is actually CALLED from the wired components:
- ExecutionObserver.record_stage_transition -> emit_stage (every transition)
- PhaseAOrchestrator -> emit_pipeline_run at run start + terminal state
- PhaseBOrchestrator -> emit_pipeline_run at its terminal states
- create_app puts a singleton emitter on app.state
"""

from __future__ import annotations

from typing import Any, ClassVar

from fastapi.testclient import TestClient
from tests.unit.test_orchestrator.test_phase_b_orchestrator import (  # noqa: F401
    REPO,
    _approve_phase_a,
    _happy_downloader,
    env,
)

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.audit.audit_store import AuditStore
from ci_agent.config.settings import Settings
from ci_agent.core.models.common import StageStatus
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.db.models import RunRecord
from ci_agent.ingress.app import create_app
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import PhaseAOrchestrator
from ci_agent.orchestrator.phase_b_orchestrator import PhaseBOrchestrator
from ci_agent.telemetry.pipeline_event import PipelineRunEvent, StageEvent


class _RecordingEmitter:
    """Test double capturing every emitted event (never raises)."""

    def __init__(self) -> None:
        self.pipeline_events: list[PipelineRunEvent] = []
        self.stage_events: list[StageEvent] = []

    def emit_pipeline_run(self, event: PipelineRunEvent) -> None:
        self.pipeline_events.append(event)

    def emit_stage(self, event: StageEvent) -> None:
        self.stage_events.append(event)

    def emit_worker(self, event: Any) -> None:  # pragma: no cover - unused here
        self.worker_events = [event]


class TestObserverWiring:
    def _observer(self, tmp_path: Any) -> tuple[ExecutionObserver, _RecordingEmitter]:
        engine = create_engine(f"sqlite:///{tmp_path / 'obs-tel.db'}")
        Base.metadata.create_all(engine)
        session_factory = get_session_factory(engine)
        audit_store = AuditStore(session_factory)
        emitter = _RecordingEmitter()
        observer = ExecutionObserver(session_factory, audit_store, telemetry_emitter=emitter)
        return observer, emitter

    def test_every_recorded_transition_emits_a_stage_event(self, tmp_path) -> None:
        observer, emitter = self._observer(tmp_path)
        observer.record_stage_transition("run-1", "sast", StageStatus.RUNNING)
        observer.record_stage_transition("run-1", "sast", StageStatus.PASSED, exit_code=0)
        assert len(emitter.stage_events) == 2
        first, second = emitter.stage_events
        assert first.stage_id == "sast"
        assert first.task_type == "scan"  # explicit STAGE_TASK_TYPES table
        assert first.status is StageStatus.RUNNING
        assert first.attributes["action"] == "created"
        assert second.status is StageStatus.PASSED
        assert second.exit_code == 0

    def test_observer_without_emitter_stays_silent_and_works(self, tmp_path) -> None:
        engine = create_engine(f"sqlite:///{tmp_path / 'obs-quiet.db'}")
        Base.metadata.create_all(engine)
        session_factory = get_session_factory(engine)
        observer = ExecutionObserver(session_factory, AuditStore(session_factory))
        record = observer.record_stage_transition("run-2", "unit_tests", StageStatus.PASSED)
        assert record.status == "passed"


class TestOrchestratorWiring:
    def test_phase_a_emits_run_started_and_terminal(self, env) -> None:
        emitter = _RecordingEmitter()

        class _FakeAdapter:
            def compile(
                self, plan: Any, metadata: dict[str, str] | None = None
            ) -> CompiledArtifact:
                return CompiledArtifact(
                    kind="github_actions_workflow",
                    content="name: fake",
                    content_hash="x",
                    metadata=metadata or {},
                )

            def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
                return DispatchRef(
                    run_id=run_id,
                    repository=artifact.metadata["repository"],
                    branch=f"ci-agent/{run_id}",
                )

        class _FakePDP:
            def evaluate_gate(self, stage_id: str, facts: Any) -> Any:
                class _Decision:
                    decision = None
                    reasons: ClassVar[list[str]] = []
                    exception_ids: ClassVar[list[str]] = []

                from ci_agent.core.models.common import PolicyDecision
                from ci_agent.policy.models import PolicyDecisionResult

                return PolicyDecisionResult(
                    decision=PolicyDecision.PASS,
                    policy_family="aggregated",
                    policy_version="1.0.0",
                )

            @property
            def policy_version(self) -> str:
                return "1.0.0"

        class _FakeGitHub:
            def post_check_run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
                return {"id": 1}

        from tests.unit.test_orchestrator.test_spec_drift_guard import (
            _guard_from_env,
            _planner_from_env,
        )

        orchestrator = PhaseAOrchestrator(
            audit_store=env["audit_store"],
            session_factory=env["session_factory"],
            project_registry=env["registry"],
            planner=_planner_from_env(env),
            pdp=_FakePDP(),
            adapter=_FakeAdapter(),  # type: ignore[arg-type]
            github_client=_FakeGitHub(),  # type: ignore[arg-type]
            concurrency_guard=_guard_from_env(env),
            policy_spec_version="1.0.0",
            require_human_approval_for=frozenset(),
            telemetry_emitter=emitter,  # type: ignore[arg-type]
        )
        env["audit_store"].create_run(
            run_id="run-tel-1",
            project_id=REPO,
            repository=REPO,
            trigger_type="push",
            source_sha="cafe1234",
        )
        result = orchestrator.advance("run-tel-1", {"type": "run_created"})
        assert result is not None and result.get("dispatched") is True

        # Drive the six tool stages to completion so Phase A reaches its
        # terminal state (merge_decision_published via auto-approval). The
        # observer records the stage rows first — exactly the production
        # wiring (observer records, then notifies the orchestrator).
        from ci_agent.observer.execution_observer import ExecutionObserver

        observer = ExecutionObserver(env["session_factory"], env["audit_store"])
        for stage in (
            "checkout",
            "format_lint",
            "sast",
            "unit_tests",
            "secret_scan",
            "dependency_scan",
        ):
            observer.record_stage_transition("run-tel-1", stage, StageStatus.PASSED)
            orchestrator.on_stage_transition("run-tel-1", stage, "passed")

        # Run start (first transition) + terminal (merge_decision_published
        # is Phase A's terminal; the approval rule auto-approves low tier).
        event_types = [e.event_type for e in emitter.pipeline_events]
        assert "run_started" in event_types
        assert "run_terminal" in event_types
        started = next(e for e in emitter.pipeline_events if e.event_type == "run_started")
        assert started.status is StageStatus.RUNNING
        assert started.runner == "linux"  # the profile's runner field (OS)
        terminal = next(e for e in emitter.pipeline_events if e.event_type == "run_terminal")
        assert terminal.status is StageStatus.PASSED
        with env["session_factory"]() as session:
            assert session.get(RunRecord, "run-tel-1").current_state == "merge_decision_published"

    def test_phase_b_emits_terminal_event(self, env) -> None:
        emitter = _RecordingEmitter()
        orchestrator = env["make_orchestrator"](
            downloader=_happy_downloader,
        )
        # Rebuild the orchestrator with the emitter attached.
        from tests.unit.test_orchestrator.test_spec_drift_guard import (
            _guard_from_env,
            _planner_from_env,
        )

        orchestrator = PhaseBOrchestrator(
            audit_store=env["audit_store"],
            session_factory=env["session_factory"],
            project_registry=env["registry"],
            planner=_planner_from_env(env),
            pdp=env["pdp"],
            adapter=env["adapter"],  # type: ignore[arg-type]
            github_client=env["github"],  # type: ignore[arg-type]
            concurrency_guard=_guard_from_env(env),
            policy_spec_version=env["policy_spec"].policy_version,
            sbom_service=env["sbom_service"],
            signing_service=env["signing_service"],
            exception_service=env["exceptions"],
            evidence_downloader=_happy_downloader,
            telemetry_emitter=emitter,  # type: ignore[arg-type]
        )
        _approve_phase_a(env, "run-tel-b")
        with env["session_factory"]() as session:
            run = session.get(RunRecord, "run-tel-b")
            assert run is not None
            run.source_sha = "cafe1234"
            session.commit()
        assert orchestrator.start("run-tel-b")["phase_b"] == "dispatched"
        # Drive to a terminal state: a failed stage parks in FAILED.
        orchestrator.on_stage_transition("run-tel-b", "full_build", "failed")
        terminals = [e for e in emitter.pipeline_events if e.event_type == "run_terminal"]
        assert terminals, "Phase B must emit its terminal state"
        assert terminals[-1].status is StageStatus.FAILED
        assert terminals[-1].attributes["phase"] == "phase_b"


class TestAppWiring:
    def test_app_state_carries_a_singleton_emitter(self, tmp_path) -> None:
        settings = Settings(
            env="local",
            database_url=f"sqlite:///{tmp_path / 'app-tel.db'}",
        )
        with TestClient(create_app(settings)) as client:
            emitter = client.app.state.telemetry_emitter  # type: ignore[attr-defined]
            assert emitter is not None
            # The SAME instance is wired into the observer and orchestrators.
            assert client.app.state.observer._telemetry is emitter  # type: ignore[attr-defined]
            assert client.app.state.orchestrator._telemetry is emitter  # type: ignore[attr-defined]
            assert (
                client.app.state.phase_b_orchestrator._telemetry is emitter  # type: ignore[attr-defined]
            )
