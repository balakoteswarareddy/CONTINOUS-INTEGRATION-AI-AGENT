"""Batch 5.1 Item 3: combined approval rule — risk-tier policy + pipeline flag.

The five documented cases plus the policy-list generalization test
(``require_human_approval_for`` containing ``medium``).

Rule (Section 4.1 + Section 6, additive):
    approve_required = risk_tier in require_human_approval_for
                       OR pipeline_spec.approvals_required
Every trigger that fires is recorded in the audit trail
(``approval_required`` event + transition reason).
"""

from __future__ import annotations

import json
from typing import Any

from tests.unit.test_projects.test_project_registry import (
    INTAKE_SCHEMA,
    _answers,
    _spec_document,
)

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision, RiskTier, StageStatus
from ci_agent.db.models import ProjectProfileRecord, RunRecord
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import (
    PhaseAOrchestrator,
)
from ci_agent.orchestrator.run_state import RunState
from ci_agent.policy.models import PolicyDecisionResult
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard

REPO = "example-org/payments-api"


class _PassPDP:
    def evaluate_gate(self, stage_id: str, facts: Any) -> PolicyDecisionResult:
        return PolicyDecisionResult(
            decision=PolicyDecision.PASS,
            reasons=[],
            policy_family="aggregated",
            policy_version="1.0.0",
        )

    @property
    def policy_version(self) -> str:
        return "1.0.0"


def _pass_pdp() -> _PassPDP:
    return _PassPDP()


class _FakeAdapter:
    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> Any:
        from ci_agent.adapters.base import CompiledArtifact

        return CompiledArtifact(
            kind="github_actions_workflow",
            content="name: fake",
            content_hash="x",
            metadata=metadata or {},
        )

    def dispatch(self, artifact: Any, run_id: str) -> Any:
        from ci_agent.adapters.base import DispatchRef

        return DispatchRef(
            run_id=run_id, repository=artifact.metadata["repository"], branch=f"ci-agent/{run_id}"
        )


class _FakeGitHub:
    def post_check_run(self, repository: str, sha: str, **kwargs: Any) -> dict[str, Any]:
        return {"id": 1}


def _orchestrator(
    session_factory,
    audit_store: AuditStore,
    require_for: list[str],
) -> PhaseAOrchestrator:
    from ci_agent.governance import load_policy_spec
    from ci_agent.planner.planner import Planner
    from ci_agent.planner.templates.template_registry import TemplateRegistry

    return PhaseAOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=ProjectRegistry(session_factory),
        planner=Planner(TemplateRegistry(), load_policy_spec(local_dev_override=True)),
        pdp=_PassPDP(),  # type: ignore[arg-type]
        adapter=_FakeAdapter(),  # type: ignore[arg-type]
        github_client=_FakeGitHub(),  # type: ignore[arg-type]
        concurrency_guard=ConcurrencyGuard(5),
        policy_spec_version="1.0.0",
        require_human_approval_for=frozenset(RiskTier(tier) for tier in require_for),
    )


def _onboard(
    session_factory, registry: ProjectRegistry, risk_tier: str, approvals_required: bool
) -> None:
    registry.register_project(
        intake_answers=_answers(), intake_schema=INTAKE_SCHEMA, repository=REPO
    )
    with session_factory() as session:
        record = session.get(ProjectProfileRecord, REPO)
        stored = json.loads(record.profile_json)
        stored["risk_tier"] = risk_tier
        record.profile_json = json.dumps(stored)
        record.risk_tier = risk_tier
        session.commit()
    spec_document = _spec_document()
    spec_document["approvals_required"] = approvals_required
    registry.register_pipeline_spec(REPO, spec_document)


def _run_to_policy_gate(
    session_factory,
    audit_store: AuditStore,
    orchestrator: PhaseAOrchestrator,
    observer: ExecutionObserver,
    run_id: str,
) -> dict[str, Any] | None:
    """Onboard + create run + pass all tool stages; returns the gate result."""
    audit_store.create_run(
        run_id=run_id,
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )
    orchestrator.advance(run_id, {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        observer.record_stage_transition(run_id, stage, StageStatus.PASSED)
        orchestrator.on_stage_transition(run_id, stage, "passed")
    observer.record_stage_transition(run_id, "dependency_scan", StageStatus.PASSED)
    return orchestrator.on_stage_transition(run_id, "dependency_scan", "passed")


def _approval_events(audit_store: AuditStore, run_id: str) -> list[dict[str, Any]]:
    return [
        json.loads(entry.payload_json)
        for entry in audit_store.get_audit_trail(run_id)
        if entry.event_type == "approval_required"
    ]


# ------------------------------------------------- the five documented cases


def test_case1_high_risk_flag_false_requires_approval(session_factory, audit_store):
    registry = ProjectRegistry(session_factory)
    _onboard(session_factory, registry, "high", approvals_required=False)
    orch = _orchestrator(session_factory, audit_store, require_for=["high", "regulated"])
    obs = ExecutionObserver(session_factory, audit_store)

    result = _run_to_policy_gate(session_factory, audit_store, orch, obs, "run-ap-1")

    assert result["state"] == RunState.AWAITING_APPROVAL.value
    assert result["triggers"] == ["risk_tier:high"]
    with session_factory() as session:
        assert session.get(RunRecord, "run-ap-1").current_state == "awaiting_approval"
    assert _approval_events(audit_store, "run-ap-1") == [{"triggers": ["risk_tier:high"]}]


def test_case2_low_risk_flag_true_requires_approval(session_factory, audit_store):
    registry = ProjectRegistry(session_factory)
    _onboard(session_factory, registry, "low", approvals_required=True)
    orch = _orchestrator(session_factory, audit_store, require_for=["high", "regulated"])
    obs = ExecutionObserver(session_factory, audit_store)

    result = _run_to_policy_gate(session_factory, audit_store, orch, obs, "run-ap-2")

    assert result["state"] == RunState.AWAITING_APPROVAL.value
    assert result["triggers"] == ["pipeline_spec.approvals_required"]
    assert _approval_events(audit_store, "run-ap-2") == [
        {"triggers": ["pipeline_spec.approvals_required"]}
    ]


def test_case3_low_risk_flag_false_auto_approves(session_factory, audit_store):
    registry = ProjectRegistry(session_factory)
    _onboard(session_factory, registry, "low", approvals_required=False)
    orch = _orchestrator(session_factory, audit_store, require_for=["high", "regulated"])
    obs = ExecutionObserver(session_factory, audit_store)

    result = _run_to_policy_gate(session_factory, audit_store, orch, obs, "run-ap-3")

    assert result["state"] == RunState.MERGE_DECISION_PUBLISHED.value
    assert result["approved"] is True
    with session_factory() as session:
        assert session.get(RunRecord, "run-ap-3").current_state == "merge_decision_published"
    assert _approval_events(audit_store, "run-ap-3") == []


def test_case4_high_risk_flag_true_lists_both_triggers(session_factory, audit_store):
    registry = ProjectRegistry(session_factory)
    _onboard(session_factory, registry, "high", approvals_required=True)
    orch = _orchestrator(session_factory, audit_store, require_for=["high", "regulated"])
    obs = ExecutionObserver(session_factory, audit_store)

    result = _run_to_policy_gate(session_factory, audit_store, orch, obs, "run-ap-4")

    assert result["state"] == RunState.AWAITING_APPROVAL.value
    assert result["triggers"] == ["risk_tier:high", "pipeline_spec.approvals_required"]
    trail = audit_store.get_audit_trail("run-ap-4")
    transition_reasons = [
        json.loads(entry.payload_json).get("reason", "")
        for entry in trail
        if entry.event_type == "run_state_transition"
    ]
    assert any(
        "risk_tier:high" in reason and "pipeline_spec.approvals_required" in reason
        for reason in transition_reasons
    )


def test_case5_policy_list_with_medium_requires_approval_for_medium(
    session_factory, audit_store
) -> None:
    """The hardcoded ``== "high"`` check is gone: the POLICY list decides."""
    registry = ProjectRegistry(session_factory)
    _onboard(session_factory, registry, "medium", approvals_required=False)
    orch = _orchestrator(session_factory, audit_store, require_for=["medium", "high"])
    obs = ExecutionObserver(session_factory, audit_store)

    result = _run_to_policy_gate(session_factory, audit_store, orch, obs, "run-ap-5")

    assert result["state"] == RunState.AWAITING_APPROVAL.value
    assert result["triggers"] == ["risk_tier:medium"]


def test_medium_not_listed_auto_approves(session_factory, audit_store) -> None:
    """Corollary: a tier OUTSIDE the configured list never requires approval."""
    registry = ProjectRegistry(session_factory)
    _onboard(session_factory, registry, "medium", approvals_required=False)
    orch = _orchestrator(session_factory, audit_store, require_for=["high", "regulated"])
    obs = ExecutionObserver(session_factory, audit_store)

    result = _run_to_policy_gate(session_factory, audit_store, orch, obs, "run-ap-6")

    assert result["state"] == RunState.MERGE_DECISION_PUBLISHED.value
