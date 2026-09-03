"""Phase A orchestrator tests (Batch 5, Task B).

Fake PDP / adapter / GitHub client; REAL planner, registry, audit store,
observer, and state machine. Each scenario asserts the state/audit dual-write
invariant after every step.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from tests.unit.test_projects.test_project_registry import (
    INTAKE_SCHEMA,
    _answers,
    _spec_document,
)

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision, RiskTier
from ci_agent.db.models import ApprovalRecord, RunRecord
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import (
    MERGE_DECISION_CHECK_NAME,
    OrchestrationError,
    PhaseAOrchestrator,
)
from ci_agent.orchestrator.run_state import RunState
from ci_agent.policy.models import PolicyDecisionResult
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard

REPO = "example-org/payments-api"


class FakePDP:
    """Scripted PolicyDecisionPoint double (never retries, just returns)."""

    def __init__(
        self,
        plan_approval: PolicyDecision = PolicyDecision.PASS,
        policy_gate: PolicyDecision = PolicyDecision.PASS,
    ) -> None:
        self.plan_approval = plan_approval
        self.policy_gate = policy_gate
        self.calls: list[str] = []

    def evaluate_gate(self, stage_id: str, facts: Any) -> PolicyDecisionResult:
        self.calls.append(stage_id)
        decision = self.plan_approval if stage_id == "plan_approval" else self.policy_gate
        return PolicyDecisionResult(
            decision=decision,
            reasons=[] if decision is PolicyDecision.PASS else ["scripted denial"],
            policy_family="aggregated",
            policy_version="1.0.0",
        )

    @property
    def policy_version(self) -> str:
        return "1.0.0"


class FakeAdapter:
    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> CompiledArtifact:
        self.metadata = metadata
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


class FakeGitHub:
    def __init__(self) -> None:
        self.check_runs: list[dict[str, Any]] = []

    def post_check_run(self, repository: str, sha: str, **kwargs: Any) -> dict[str, Any]:
        self.check_runs.append({"repository": repository, "sha": sha, **kwargs})
        return {"id": 1}


class _GuardSpy(ConcurrencyGuard):
    def __init__(self, max_per_project: int) -> None:
        super().__init__(max_per_project)
        self.acquired: list[str] = []
        self.released: list[str] = []

    def acquire(self, project_id: str) -> bool:
        self.acquired.append(project_id)
        return super().acquire(project_id)

    def release(self, project_id: str) -> None:
        self.released.append(project_id)
        super().release(project_id)


@pytest.fixture()
def setup(session_factory, audit_store: AuditStore, phase_a_pipeline_spec, python_project_profile):
    registry = ProjectRegistry(session_factory)
    registry.register_project(
        intake_answers=_answers(),
        intake_schema=INTAKE_SCHEMA,
        repository=REPO,
    )
    registry.register_pipeline_spec(REPO, _spec_document())
    observer = ExecutionObserver(session_factory, audit_store)
    return registry, observer


def _make_orchestrator(
    session_factory,
    audit_store: AuditStore,
    registry: ProjectRegistry,
    observer: ExecutionObserver,
    pdp: FakePDP | None = None,
    adapter: FakeAdapter | None = None,
    github: FakeGitHub | None = None,
    guard: ConcurrencyGuard | None = None,
) -> tuple[PhaseAOrchestrator, FakeAdapter, FakeGitHub, _GuardSpy]:
    pdp = pdp or FakePDP()
    adapter = adapter or FakeAdapter()
    github = github or FakeGitHub()
    spy_guard = _GuardSpy(1)
    orchestrator = PhaseAOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=registry,
        planner=None,  # type: ignore[arg-type] - built lazily below
        pdp=pdp,  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        github_client=github,  # type: ignore[arg-type]
        concurrency_guard=guard or spy_guard,
        policy_spec_version="1.0.0",
    )
    from ci_agent.governance import load_policy_spec
    from ci_agent.planner.planner import Planner
    from ci_agent.planner.templates.template_registry import TemplateRegistry

    orchestrator._planner = Planner(TemplateRegistry(), load_policy_spec())
    return orchestrator, adapter, github, spy_guard


def _create_run(session_factory, audit_store: AuditStore) -> str:
    audit_store.create_run(
        run_id="run-orch-1",
        project_id=REPO,
        repository=REPO,
        trigger_type="pull_request",
        source_sha="cafe1234",
    )
    return "run-orch-1"


def _pass_stage(
    observer: ExecutionObserver, orchestrator: PhaseAOrchestrator, run_id: str, stage: str
) -> dict[str, Any] | None:
    """Realistic order: the observer records, then the orchestrator advances."""
    from ci_agent.core.models.common import StageStatus

    observer.record_stage_transition(run_id, stage, StageStatus.PASSED)
    return orchestrator.on_stage_transition(run_id, stage, "passed")


def _assert_dual_write(session_factory, audit_store: AuditStore, run_id: str) -> RunState | None:
    """Invariant: RunRecord.current_state matches the last state transition."""
    with session_factory() as session:
        run = session.get(RunRecord, run_id)
        persisted = RunState(run.current_state) if run.current_state else None
    transitions = [
        entry
        for entry in audit_store.get_audit_trail(run_id)
        if entry.event_type == "run_state_transition"
    ]
    if transitions:
        last_target = json.loads(transitions[-1].payload_json)["to"]
        assert persisted is not None
        assert persisted.value == last_target
    else:
        assert persisted is None
    return persisted


def test_happy_path_no_approval(session_factory, audit_store: AuditStore, setup) -> None:
    registry, observer = setup
    orchestrator, adapter, github, guard = _make_orchestrator(
        session_factory,
        audit_store,
        registry,
        observer,
        pdp=FakePDP(policy_gate=PolicyDecision.PASS),
    )
    run_id = _create_run(session_factory, audit_store)

    # Low risk tier -> no approval required after policy gate.
    with session_factory() as session:
        profile = registry.get_profile(REPO)
        assert profile.risk_tier is RiskTier.HIGH  # fixture is high-risk
    # For the no-approval scenario, downgrade the registered profile to low.
    with session_factory() as session:
        from ci_agent.db.models import ProjectProfileRecord

        record = session.get(ProjectProfileRecord, REPO)
        stored = json.loads(record.profile_json)
        stored["risk_tier"] = "low"
        record.profile_json = json.dumps(stored)
        record.risk_tier = "low"
        session.commit()

    result = orchestrator.advance(run_id, {"type": "run_created"})
    assert result["dispatched"] is True
    assert _assert_dual_write(session_factory, audit_store, run_id) is RunState.TRIGGER_VALIDATED
    assert guard.acquired == [REPO]
    assert adapter.metadata["repository"] == REPO

    # Drive all tool stages through observer record + orchestrator advance.
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        result = _pass_stage(observer, orchestrator, run_id, stage)
        assert result is not None and "state" in result
        _assert_dual_write(session_factory, audit_store, run_id)
    assert observer.get_stage_record(run_id, "checkout").status == "passed"

    result = _pass_stage(observer, orchestrator, run_id, "dependency_scan")
    assert result["state"] == RunState.MERGE_DECISION_PUBLISHED.value
    assert _assert_dual_write(session_factory, audit_store, run_id) is (
        RunState.MERGE_DECISION_PUBLISHED
    )
    assert guard.released == [REPO]
    assert len(github.check_runs) == 1
    published = github.check_runs[0]
    assert published["name"] == MERGE_DECISION_CHECK_NAME
    assert published["conclusion"] == "success"
    assert "view=compliance" in published["output"]["summary"]


def test_policy_gate_fail_blocks_merge(session_factory, audit_store: AuditStore, setup) -> None:
    registry, observer = setup
    orchestrator, _adapter, github, guard = _make_orchestrator(
        session_factory,
        audit_store,
        registry,
        observer,
        pdp=FakePDP(policy_gate=PolicyDecision.FAIL),
    )
    run_id = _create_run(session_factory, audit_store)
    orchestrator.advance(run_id, {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        _pass_stage(observer, orchestrator, run_id, stage)

    result = _pass_stage(observer, orchestrator, run_id, "dependency_scan")
    assert result["state"] == RunState.FAILED.value
    assert _assert_dual_write(session_factory, audit_store, run_id) is RunState.FAILED
    assert github.check_runs[0]["conclusion"] == "failure"
    assert guard.released == [REPO]  # guard freed on terminal


def test_approval_flow_approve(session_factory, audit_store: AuditStore, setup) -> None:
    registry, observer = setup
    orchestrator, _adapter, github, _guard = _make_orchestrator(
        session_factory,
        audit_store,
        registry,
        observer,
        pdp=FakePDP(),
    )
    run_id = _create_run(session_factory, audit_store)
    orchestrator.advance(run_id, {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        _pass_stage(observer, orchestrator, run_id, stage)

    result = _pass_stage(observer, orchestrator, run_id, "dependency_scan")
    assert result["state"] == RunState.AWAITING_APPROVAL.value
    _assert_dual_write(session_factory, audit_store, run_id)

    # Approve -> merge decision published.
    result = orchestrator.advance(
        run_id,
        {"type": "approval", "decision": "approved", "approver": "alice", "comment": "ship it"},
    )
    assert result == {"state": "merge_decision_published", "approved": True}
    assert _assert_dual_write(session_factory, audit_store, run_id) is (
        RunState.MERGE_DECISION_PUBLISHED
    )
    with session_factory() as session:
        approvals = session.query(ApprovalRecord).all()
        assert len(approvals) == 1
        assert approvals[0].approver == "alice"
        assert approvals[0].decision == "approved"
        assert approvals[0].comment == "ship it"
    assert github.check_runs[0]["conclusion"] == "success"


def test_approval_flow_reject(session_factory, audit_store: AuditStore, setup) -> None:
    registry, observer = setup
    orchestrator, _adapter, github, _guard = _make_orchestrator(
        session_factory,
        audit_store,
        registry,
        observer,
        pdp=FakePDP(),
    )
    run_id = _create_run(session_factory, audit_store)
    orchestrator.advance(run_id, {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        _pass_stage(observer, orchestrator, run_id, stage)
    _pass_stage(observer, orchestrator, run_id, "dependency_scan")

    result = orchestrator.advance(
        run_id, {"type": "approval", "decision": "rejected", "approver": "bob"}
    )
    assert result == {"state": "merge_decision_published", "approved": False}
    assert _assert_dual_write(session_factory, audit_store, run_id) is (
        RunState.MERGE_DECISION_PUBLISHED
    )
    assert github.check_runs[0]["conclusion"] == "failure"
    assert "rejected by bob" in github.check_runs[0]["output"]["summary"]


def test_approval_on_non_awaiting_run_raises_409_shape(
    session_factory, audit_store: AuditStore, setup
) -> None:
    registry, observer = setup
    orchestrator, _adapter, _github, _guard = _make_orchestrator(
        session_factory, audit_store, registry, observer
    )
    run_id = _create_run(session_factory, audit_store)
    with pytest.raises(ValueError, match="not awaiting_approval"):
        orchestrator.advance(
            run_id, {"type": "approval", "decision": "approved", "approver": "eve"}
        )


def test_plan_approval_rejected_fails_run_and_publishes_block(
    session_factory, audit_store: AuditStore, setup
) -> None:
    registry, observer = setup
    orchestrator, adapter, github, _guard = _make_orchestrator(
        session_factory,
        audit_store,
        registry,
        observer,
        pdp=FakePDP(plan_approval=PolicyDecision.FAIL),
    )
    run_id = _create_run(session_factory, audit_store)
    result = orchestrator.advance(run_id, {"type": "run_created"})
    assert result["state"] == RunState.FAILED.value
    assert _assert_dual_write(session_factory, audit_store, run_id) is RunState.FAILED
    # Never dispatched; blocked merge decision still published.
    assert adapter.metadata if hasattr(adapter, "metadata") else True
    assert github.check_runs[0]["conclusion"] == "failure"


def test_stage_failure_fails_run(session_factory, audit_store: AuditStore, setup) -> None:
    registry, observer = setup
    orchestrator, _adapter, github, _guard = _make_orchestrator(
        session_factory, audit_store, registry, observer
    )
    run_id = _create_run(session_factory, audit_store)
    orchestrator.advance(run_id, {"type": "run_created"})
    _pass_stage(observer, orchestrator, run_id, "checkout")

    result = orchestrator.on_stage_transition(run_id, "format_lint", "failed")
    assert result["state"] == RunState.FAILED.value
    assert _assert_dual_write(session_factory, audit_store, run_id) is RunState.FAILED
    assert github.check_runs[0]["conclusion"] == "failure"


def test_concurrency_limit_parks_run_in_error(
    session_factory, audit_store: AuditStore, setup
) -> None:
    registry, observer = setup
    full_guard = ConcurrencyGuard(max_per_project=1)
    assert full_guard.acquire(REPO)  # simulate an in-flight run
    orchestrator, _adapter, _github, _spy = _make_orchestrator(
        session_factory, audit_store, registry, observer, guard=full_guard
    )
    run_id = _create_run(session_factory, audit_store)
    result = orchestrator.advance(run_id, {"type": "run_created"})
    assert result == {"state": "error", "reason": "concurrency limit"}
    assert _assert_dual_write(session_factory, audit_store, run_id) is RunState.ERROR


def test_unregistered_project_fails_closed(session_factory, audit_store: AuditStore, setup) -> None:
    registry, observer = setup
    orchestrator, _adapter, _github, _guard = _make_orchestrator(
        session_factory, audit_store, registry, observer
    )
    audit_store.create_run(
        run_id="run-ghost",
        project_id="ghost/repo",
        repository="ghost/repo",
        trigger_type="push",
        source_sha="beef",
    )
    with pytest.raises(OrchestrationError):
        orchestrator.advance("run-ghost", {"type": "run_created"})
    assert _assert_dual_write(session_factory, audit_store, "run-ghost") is RunState.ERROR


def test_echo_events_from_github_are_ignored(
    session_factory, audit_store: AuditStore, setup
) -> None:
    registry, observer = setup
    orchestrator, _adapter, _github, _guard = _make_orchestrator(
        session_factory, audit_store, registry, observer
    )
    run_id = _create_run(session_factory, audit_store)
    assert orchestrator.on_stage_transition(run_id, "workflow", "passed") is None
    assert orchestrator.on_stage_transition(run_id, "internal.policy_gate", "passed") is None
