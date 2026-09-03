"""Batch 5.1 Item 4: RunRecord.status is deprecated; current_state is the truth.

Proves by construction that the two fields cannot disagree:
* ``RunRecord.status`` is an insert-only legacy column, frozen at "accepted";
* every external-facing status string derives from ``current_state`` via
  :func:`ci_agent.db.models.run_status_from_state`;
* the derivation is total over all 14 RunState values (+ None).
"""

from __future__ import annotations

import json

from tests.unit.test_orchestrator.test_approval_rule import (
    REPO,
    _FakeAdapter,
    _FakeGitHub,
    _onboard,
    _pass_pdp,
)

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import StageStatus
from ci_agent.db.models import RunRecord, run_status_from_state
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import PhaseAOrchestrator
from ci_agent.orchestrator.run_state import RunState
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard


def _make_orchestrator(session_factory, audit_store: AuditStore) -> PhaseAOrchestrator:
    from ci_agent.governance import load_policy_spec
    from ci_agent.planner.planner import Planner
    from ci_agent.planner.templates.template_registry import TemplateRegistry

    return PhaseAOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=ProjectRegistry(session_factory),
        planner=Planner(TemplateRegistry(), load_policy_spec(local_dev_override=True)),
        pdp=_pass_pdp(),  # type: ignore[arg-type]
        adapter=_FakeAdapter(),  # type: ignore[arg-type]
        github_client=_FakeGitHub(),  # type: ignore[arg-type]
        concurrency_guard=ConcurrencyGuard(5),
        policy_spec_version="1.0.0",
        require_human_approval_for=frozenset(),
    )


def test_mapping_is_total_over_all_states_and_none() -> None:
    assert run_status_from_state(None) == "accepted"
    for state in RunState:
        derived = run_status_from_state(state.value)
        assert derived != ""
        if state is RunState.MERGE_DECISION_PUBLISHED:
            assert derived == "published"
        if state is RunState.AWAITING_APPROVAL:
            assert derived == "awaiting_approval"
        if state in (RunState.FAILED, RunState.ERROR):
            assert derived == state.value


def test_unknown_state_maps_fail_closed_to_error() -> None:
    assert run_status_from_state("some-future-state") == "error"


def test_status_column_frozen_while_current_state_advances(
    session_factory, audit_store: AuditStore
) -> None:
    """Drive a run through several transitions; assert no drift at any step."""
    orchestrator = _make_orchestrator(session_factory, audit_store)
    observer = ExecutionObserver(session_factory, audit_store)

    registry = ProjectRegistry(session_factory)
    _onboard(session_factory, registry, "low", approvals_required=False)

    audit_store.create_run(
        run_id="run-drift-1",
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )

    def frozen_and_consistent() -> str:
        with session_factory() as session:
            run = session.get(RunRecord, "run-drift-1")
            # The legacy column NEVER moves off the insert default...
            assert run.status == "accepted"
            # ...and the derived display always tracks current_state.
            return run_status_from_state(run.current_state)

    orchestrator.advance("run-drift-1", {"type": "run_created"})
    assert frozen_and_consistent() == "in_progress"

    observed: list[str] = ["accepted"]  # current_state None -> "accepted"
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        observer.record_stage_transition("run-drift-1", stage, StageStatus.PASSED)
        orchestrator.on_stage_transition("run-drift-1", stage, "passed")
        observed.append(frozen_and_consistent())
    assert "in_progress" in observed

    observer.record_stage_transition("run-drift-1", "dependency_scan", StageStatus.PASSED)
    orchestrator.on_stage_transition("run-drift-1", "dependency_scan", "passed")

    with session_factory() as session:
        run = session.get(RunRecord, "run-drift-1")
        assert run.status == "accepted"  # frozen even at the terminal state
        assert run.current_state == "merge_decision_published"
    assert frozen_and_consistent() == "published"
    # The derived status actually MOVED through the run's life (the mapping
    # tracks current_state; it is not a constant).
    assert observed[-1] == "in_progress"


def test_api_status_field_is_derived_not_stored(tmp_path) -> None:
    """GET /runs/{run_id} derives `status` from current_state: mutating
    current_state changes the API response while the legacy column stays
    frozen at "accepted"."""
    from fastapi.testclient import TestClient

    from ci_agent.config.settings import Settings
    from ci_agent.db.base import Base, create_engine, get_session_factory
    from ci_agent.ingress.app import create_app

    database_path = tmp_path / "status-api.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    engine.dispose()
    settings = Settings(env="local", database_url=f"sqlite:///{database_path}")
    application = create_app(settings)
    session_factory = get_session_factory(engine)
    AuditStore(session_factory).create_run(
        run_id="run-api-1",
        project_id="example-org/payments-api",
        repository="example-org/payments-api",
        trigger_type="push",
        source_sha="cafe1234",
    )
    with TestClient(application) as client:
        initial = client.get("/runs/run-api-1").json()
        assert initial["status"] == "accepted"  # current_state is None
        assert initial["current_state"] is None
        # Move the run's authoritative state directly (as the orchestrator
        # would through a failure path).
        with session_factory() as session:
            run = session.get(RunRecord, "run-api-1")
            run.current_state = "failed"
            session.commit()
        after = client.get("/runs/run-api-1").json()

    json.dumps(after)  # serializable
    assert after["status"] == "failed"  # derived from current_state
    assert after["current_state"] == "failed"
    with session_factory() as session:
        assert session.get(RunRecord, "run-api-1").status == "accepted"
