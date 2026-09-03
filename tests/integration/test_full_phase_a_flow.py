"""Full Phase A flow integration test (Batch 5 DoD).

Mocked GitHub (adapter + client) against REAL local OPA, three scenarios:

1. happy path — no approval required (low risk profile) -> merge decision
   published, audit chain verifiable;
2. policy gate fail -> FAILED + blocked merge decision;
3. approval required (high risk) -> AWAITING_APPROVAL -> approve -> published
   (and reject variant).

Requires OPA on ``OPA_URL`` (default localhost:8181):
    opa run --server --set=decision_logs.console=true governance/rego
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from tests.conftest import complete_intake_answers
from tests.unit.test_projects.test_project_registry import _spec_document

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision, StageStatus
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.db.models import RunRecord
from ci_agent.governance import load_intake_schema, load_policy_spec
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import (
    MERGE_DECISION_CHECK_NAME,
    PhaseAOrchestrator,
)
from ci_agent.orchestrator.run_state import RunState
from ci_agent.planner.planner import Planner
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.policy.opa_client import OPAClient
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard
from ci_agent.resolver.project_profile import ProjectProfile


def _opa_up() -> bool:
    """Probe the configured OPA URL once (import-time, cheap)."""
    import httpx

    from ci_agent.config.settings import DEFAULT_OPA_TIMEOUT_SECONDS, DEFAULT_OPA_URL

    try:
        response = httpx.get(f"{DEFAULT_OPA_URL}/health", timeout=DEFAULT_OPA_TIMEOUT_SECONDS)
        return response.status_code == 200
    except httpx.TransportError:
        return False


requires_opa = pytest.mark.skipif(not _opa_up(), reason="requires live OPA (docker-compose up opa)")

REPO = "example-org/payments-api"


class FakeAdapter:
    """Records dispatches; returns a well-formed DispatchRef."""

    def __init__(self) -> None:
        self.dispatched: list[dict[str, Any]] = []

    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> CompiledArtifact:
        self.dispatched.append({"run_id": plan.run_id, "metadata": metadata})
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
        return {"id": len(self.check_runs)}


def _profile(risk_tier: str) -> ProjectProfile:
    from tests.conftest import complete_intake_answers as _c

    base = _c()
    return ProjectProfile(
        project_id=REPO,
        business_criticality=base["business_criticality"],
        data_sensitivity=base["data_sensitivity"],
        risk_tier=risk_tier,
        repo_structure=base["repo_structure"],
        language_stack="python",
        runner=base["runner_os"],
        security_tools=["bandit", "pip-audit", "gitleaks"],
        secret_storage=base["secrets_provider"],
        coverage_requirement=80.0,
        artifact_repository=base["artifact_registry_type"],
        testing_strategy="unit+integration",
        execution_location=base["primary_execution_location"],
        policy_version_pinned="1.0.0",
        raw_intake_answers=dict(base),
    )


@pytest.fixture()
def env(tmp_path):
    """Fully wired orchestrator against real OPA with mocked GitHub."""
    engine = create_engine(f"sqlite:///{tmp_path / 'flow.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    registry = ProjectRegistry(session_factory)
    policy_spec = load_policy_spec(local_dev_override=True)
    planner = Planner(TemplateRegistry(), policy_spec)
    opa_client = OPAClient("http://127.0.0.1:8181", 2.0)
    pdp = PolicyDecisionPoint(opa_client, audit_store, policy_spec, session_factory=session_factory)
    adapter = FakeAdapter()
    github = FakeGitHub()
    orchestrator = PhaseAOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=registry,
        planner=planner,
        pdp=pdp,
        adapter=adapter,  # type: ignore[arg-type]
        github_client=github,  # type: ignore[arg-type]
        concurrency_guard=ConcurrencyGuard(3),
        policy_spec_version=policy_spec.policy_version,
        require_human_approval_for=frozenset(
            policy_spec.approval_policy.require_human_approval_for
        ),
    )
    observer = ExecutionObserver(session_factory, audit_store)
    return {
        "session_factory": session_factory,
        "audit_store": audit_store,
        "registry": registry,
        "orchestrator": orchestrator,
        "observer": observer,
        "adapter": adapter,
        "github": github,
    }


def _onboard(env: dict, risk_tier: str) -> None:
    registry: ProjectRegistry = env["registry"]
    intake_schema = load_intake_schema()
    registry.register_project(
        intake_answers=dict(complete_intake_answers()),
        intake_schema=intake_schema,
        repository=REPO,
    )
    # Post-adjust the risk tier for the scenario (resolver derives "high").
    from ci_agent.db.models import ProjectProfileRecord

    with env["session_factory"]() as session:
        record = session.get(ProjectProfileRecord, REPO)
        stored = json.loads(record.profile_json)
        stored["risk_tier"] = risk_tier
        record.profile_json = json.dumps(stored)
        record.risk_tier = risk_tier
        session.commit()
    registry.register_pipeline_spec(REPO, _spec_document())


def _create_run(env: dict, run_id: str) -> None:
    env["audit_store"].create_run(
        run_id=run_id,
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )


def _pass(env: dict, run_id: str, stage: str) -> dict[str, Any] | None:
    env["observer"].record_stage_transition(run_id, stage, StageStatus.PASSED)
    return env["orchestrator"].on_stage_transition(run_id, stage, "passed")


def _assert_chain(env: dict, run_id: str) -> None:
    assert env["audit_store"].verify_chain(run_id), "audit chain must verify"


@requires_opa
def test_scenario_happy_path_no_approval(env: dict) -> None:
    _onboard(env, "low")
    _create_run(env, "run-flow-1")
    orchestrator = env["orchestrator"]

    result = orchestrator.advance("run-flow-1", {"type": "run_created"})
    assert result["dispatched"] is True
    assert env["adapter"].dispatched[0]["metadata"]["repository"] == REPO

    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        _pass(env, "run-flow-1", stage)
    result = _pass(env, "run-flow-1", "dependency_scan")
    assert result is not None
    assert result["state"] == RunState.MERGE_DECISION_PUBLISHED.value

    with env["session_factory"]() as session:
        run = session.get(RunRecord, "run-flow-1")
        assert run.current_state == RunState.MERGE_DECISION_PUBLISHED.value
        assert run.dispatch_branch == "ci-agent/run-flow-1"
    _assert_chain(env, "run-flow-1")
    assert env["github"].check_runs[0]["conclusion"] == "success"


@requires_opa
def test_scenario_policy_gate_fail(env: dict) -> None:
    _onboard(env, "low")
    _create_run(env, "run-flow-2")
    orchestrator = env["orchestrator"]
    observer = env["observer"]

    orchestrator.advance("run-flow-2", {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests"):
        _pass(env, "run-flow-2", stage)
    # The secret scan FAILS on the runner -> run fails, decision blocked.
    observer.record_stage_transition("run-flow-2", "secret_scan", StageStatus.FAILED)
    result = orchestrator.on_stage_transition("run-flow-2", "secret_scan", "failed")
    assert result["state"] == RunState.FAILED.value

    with env["session_factory"]() as session:
        run = session.get(RunRecord, "run-flow-2")
        assert run.current_state == RunState.FAILED.value
    _assert_chain(env, "run-flow-2")
    assert env["github"].check_runs[0]["conclusion"] == "failure"


@requires_opa
def test_scenario_approval_then_approve(env: dict) -> None:
    _onboard(env, "high")
    _create_run(env, "run-flow-3")
    orchestrator = env["orchestrator"]

    orchestrator.advance("run-flow-3", {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        _pass(env, "run-flow-3", stage)
    result = _pass(env, "run-flow-3", "dependency_scan")
    assert result["state"] == RunState.AWAITING_APPROVAL.value
    with env["session_factory"]() as session:
        run = session.get(RunRecord, "run-flow-3")
        assert run.current_state == RunState.AWAITING_APPROVAL.value
    _assert_chain(env, "run-flow-3")

    result = orchestrator.advance(
        "run-flow-3",
        {"type": "approval", "decision": "approved", "approver": "alice"},
    )
    assert result["approved"] is True
    with env["session_factory"]() as session:
        run = session.get(RunRecord, "run-flow-3")
        assert run.current_state == RunState.MERGE_DECISION_PUBLISHED.value
    _assert_chain(env, "run-flow-3")
    check = env["github"].check_runs[0]
    assert check["name"] == MERGE_DECISION_CHECK_NAME
    assert check["conclusion"] == "success"
    assert "view=compliance" in check["output"]["summary"]


@requires_opa
def test_scenario_approval_then_reject(env: dict) -> None:
    _onboard(env, "high")
    _create_run(env, "run-flow-4")
    orchestrator = env["orchestrator"]

    orchestrator.advance("run-flow-4", {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        _pass(env, "run-flow-4", stage)
    result = _pass(env, "run-flow-4", "dependency_scan")
    assert result["state"] == RunState.AWAITING_APPROVAL.value

    result = orchestrator.advance(
        "run-flow-4",
        {"type": "approval", "decision": "rejected", "approver": "bob", "comment": "not yet"},
    )
    assert result["approved"] is False
    with env["session_factory"]() as session:
        run = session.get(RunRecord, "run-flow-4")
        assert run.current_state == RunState.MERGE_DECISION_PUBLISHED.value
    _assert_chain(env, "run-flow-4")
    check = env["github"].check_runs[0]
    assert check["conclusion"] == "failure"
    assert "rejected by bob" in check["output"]["summary"]


@requires_opa
def test_real_pdp_gate_evaluated_against_opa(env: dict) -> None:
    """Sanity: the PDP decisions in the flow come from REAL OPA evaluations."""
    _onboard(env, "low")
    _create_run(env, "run-flow-5")
    with env["session_factory"]() as session:
        from ci_agent.db.models import PolicyDecisionRecord

        before = session.query(PolicyDecisionRecord).count()
    env["orchestrator"].advance("run-flow-5", {"type": "run_created"})
    with env["session_factory"]() as session:
        rows = session.query(PolicyDecisionRecord).all()
    assert len(rows) == before + 1
    assert rows[-1].stage_id == "plan_approval"
    assert rows[-1].decision == PolicyDecision.PASS.value
