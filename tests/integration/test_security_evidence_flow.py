"""Batch 6 DoD: full pipeline — REAL findings drive the policy gate.

1. A bandit HIGH finding (above the governed threshold of 0) fails the
   policy gate against REAL OPA — previously the same run passed/failed on
   exit codes only.
2. The same findings with a below-threshold severity profile passes.
3. The ``?view=security`` report shows real scanner/rule/severity/location.
4. Unparseable tool output fails the gate (fail-closed) instead of passing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision, StageStatus
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.governance import load_policy_spec
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import PhaseAOrchestrator
from ci_agent.planner.planner import Planner
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.policy.models import PolicyDecisionResult
from ci_agent.policy.opa_client import OPAClient
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard
from ci_agent.security.security_evidence_service import SecurityEvidenceService


def _opa_up() -> bool:
    import httpx

    from ci_agent.config.settings import DEFAULT_OPA_TIMEOUT_SECONDS, DEFAULT_OPA_URL

    try:
        response = httpx.get(f"{DEFAULT_OPA_URL}/health", timeout=DEFAULT_OPA_TIMEOUT_SECONDS)
        return response.status_code == 200
    except httpx.TransportError:
        return False


requires_opa = pytest.mark.skipif(not _opa_up(), reason="requires live OPA (docker-compose up opa)")

REPO = "example-org/payments-api"
FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "security_tool_outputs"


class _PassPDP:
    """PDP double for the plan_approval gate; the REAL PDP handles policy_gate."""

    def evaluate_gate(self, stage_id: str, facts: Any) -> PolicyDecisionResult:
        return PolicyDecisionResult(
            decision=__import__(
                "ci_agent.core.models.common", fromlist=["PolicyDecision"]
            ).PolicyDecision.PASS,
            reasons=[],
            policy_family="aggregated",
            policy_version="1.0.0",
        )

    @property
    def policy_version(self) -> str:
        return "1.0.0"


class _RoutingPDP:
    """plan_approval -> scripted PASS; policy_gate -> REAL OPA-backed PDP."""

    def __init__(self, real: PolicyDecisionPoint, scripted: _PassPDP) -> None:
        self.real = real
        self.scripted = scripted
        self.gate_results: list[PolicyDecisionResult] = []

    def evaluate_gate(self, stage_id: str, facts: Any) -> PolicyDecisionResult:
        if stage_id == "plan_approval":
            return self.scripted.evaluate_gate(stage_id, facts)
        result = self.real.evaluate_gate(stage_id, facts)
        self.gate_results.append(result)
        return result

    @property
    def policy_version(self) -> str:
        return self.real.policy_version


class _FakeAdapter:
    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> CompiledArtifact:
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


class _FakeGitHub:
    def post_check_run(self, repository: str, sha: str, **kwargs: Any) -> dict[str, Any]:
        return {"id": 1}


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'b6.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    registry = ProjectRegistry(session_factory)
    policy_spec = load_policy_spec(local_dev_override=True)
    planner = Planner(TemplateRegistry(), policy_spec)
    opa_client = OPAClient("http://127.0.0.1:8181", 2.0)
    real_pdp = PolicyDecisionPoint(
        opa_client, audit_store, policy_spec, session_factory=session_factory
    )
    pdp = _RoutingPDP(real_pdp, _PassPDP())
    orchestrator = PhaseAOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=registry,
        planner=planner,
        pdp=pdp,  # type: ignore[arg-type]
        adapter=_FakeAdapter(),  # type: ignore[arg-type]
        github_client=_FakeGitHub(),  # type: ignore[arg-type]
        concurrency_guard=ConcurrencyGuard(3),
        policy_spec_version=policy_spec.policy_version,
        require_human_approval_for=frozenset(
            policy_spec.approval_policy.require_human_approval_for
        ),
    )
    observer = ExecutionObserver(session_factory, audit_store)
    evidence = SecurityEvidenceService(session_factory, audit_store)
    return {
        "session_factory": session_factory,
        "audit_store": audit_store,
        "registry": registry,
        "orchestrator": orchestrator,
        "observer": observer,
        "evidence": evidence,
        "pdp": pdp,
    }


def _onboard_low(env: dict) -> None:
    registry: ProjectRegistry = env["registry"]
    from tests.unit.test_projects.test_project_registry import (
        INTAKE_SCHEMA,
        _answers,
        _spec_document,
    )

    registry.register_project(
        intake_answers=_answers(), intake_schema=INTAKE_SCHEMA, repository=REPO
    )
    with env["session_factory"]() as session:
        from ci_agent.db.models import ProjectProfileRecord

        record = session.get(ProjectProfileRecord, REPO)
        stored = json.loads(record.profile_json)
        stored["risk_tier"] = "low"
        record.profile_json = json.dumps(stored)
        record.risk_tier = "low"
        session.commit()
    registry.register_pipeline_spec(REPO, _spec_document())


def _drive_to_policy_gate(env: dict, run_id: str) -> dict[str, Any] | None:
    env["audit_store"].create_run(
        run_id=run_id,
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )
    orchestrator = env["orchestrator"]
    observer = env["observer"]
    orchestrator.advance(run_id, {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        observer.record_stage_transition(run_id, stage, StageStatus.PASSED)
        orchestrator.on_stage_transition(run_id, stage, "passed")
    observer.record_stage_transition(run_id, "dependency_scan", StageStatus.PASSED)
    return orchestrator.on_stage_transition(run_id, "dependency_scan", "passed")


@requires_opa
def test_bandit_high_finding_fails_policy_gate(env: dict) -> None:
    """DoD pipeline: 1 real HIGH finding -> gate FAILS (threshold high: 0)."""
    _onboard_low(env)
    evidence: SecurityEvidenceService = env["evidence"]
    evidence.collect_findings(
        "run-gate-1",
        "sast",
        "bandit",
        (FIXTURES / "bandit_with_findings.json").read_text(encoding="utf-8"),
    )
    result = _drive_to_policy_gate(env, "run-gate-1")

    assert result is not None
    assert result["state"] == "failed"
    # The gate reached OPA with the REAL finding facts and failed on the
    # governed threshold ("severity high: 1 findings exceed threshold 0").
    assert env["pdp"].gate_results
    final = env["pdp"].gate_results[-1]
    assert final.decision is PolicyDecision.FAIL
    assert any("high" in reason and "threshold 0" in reason for reason in final.reasons)
    with env["session_factory"]() as session:
        from ci_agent.db.models import PolicyDecisionRecord

        rows = session.query(PolicyDecisionRecord).filter_by(stage_id="policy_gate").all()
        assert rows[-1].decision == "fail"
        assert "high" in rows[-1].reasons_json


@requires_opa
def test_info_level_only_findings_pass_policy_gate(env: dict) -> None:
    """Below-threshold findings do NOT fail the gate (threshold low: 20)."""
    _onboard_low(env)
    evidence: SecurityEvidenceService = env["evidence"]
    evidence.collect_findings(
        "run-gate-2",
        "sast",
        "bandit",
        (FIXTURES / "bandit_clean.json").read_text(encoding="utf-8"),
    )
    result = _drive_to_policy_gate(env, "run-gate-2")
    assert result is not None
    assert result["state"] == "merge_decision_published"


@requires_opa
def test_unparseable_output_fails_gate_fail_closed(env: dict) -> None:
    """Unparseable tool output -> ParserWarning incident -> gate FAILS."""
    _onboard_low(env)
    evidence: SecurityEvidenceService = env["evidence"]
    evidence.collect_findings("run-gate-3", "sast", "bandit", "<<<not json>>>")
    assert evidence.has_parser_warnings("run-gate-3")

    result = _drive_to_policy_gate(env, "run-gate-3")
    assert result is not None
    assert result["state"] == "failed"
    final = env["pdp"].gate_results[-1]
    assert final.decision is PolicyDecision.FAIL
    # The parser warning enters the PDP facts as a HIGH finding
    # (parser_warning_unparseable_output), pushing HIGH count to 1 > the
    # governed threshold of 0 — the run FAILS closed, never "clean".
    assert any("1 findings exceed threshold 0" in reason for reason in final.reasons)
    with env["session_factory"]() as session:
        from ci_agent.db.models import PolicyDecisionRecord

        row = (
            session.query(PolicyDecisionRecord)
            .filter_by(run_id="run-gate-3", stage_id="policy_gate")
            .order_by(PolicyDecisionRecord.id.desc())
            .first()
        )
        assert row is not None and row.decision == "fail"


def test_security_report_view_real_finding_data(tmp_path) -> None:
    """DoD: ?view=security shows real scanner/rule/severity/location."""
    from ci_agent.config.settings import Settings
    from ci_agent.ingress.app import create_app

    database_path = tmp_path / "sec-report.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    engine.dispose()
    settings = Settings(env="local", database_url=f"sqlite:///{database_path}")
    application = create_app(settings)
    session_factory = get_session_factory(engine)
    store = AuditStore(session_factory)
    store.create_run(
        run_id="run-sec-view",
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )
    SecurityEvidenceService(session_factory, store).collect_findings(
        "run-sec-view",
        "sast",
        "bandit",
        (FIXTURES / "bandit_with_findings.json").read_text(encoding="utf-8"),
    )
    with TestClient(application) as client:
        response = client.get("/runs/run-sec-view/report?view=security")
    assert response.status_code == 200
    body = response.json()
    assert body["summary"] == {"high": 1, "low": 1}
    high = next(f for f in body["findings"] if f["severity"] == "high")
    assert high["scanner"] == "bandit"
    assert high["rule_id"] == "B605"
    assert high["location"] == "app/exec.py:42"
    assert high["disposition"] == "open"
    assert high["stage_id"] == "sast"
    # JSON-serializable end to end.
    json.dumps(body)
