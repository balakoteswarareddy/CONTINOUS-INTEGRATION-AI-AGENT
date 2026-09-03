"""Batch 7 DoD: a FULL mocked Phase A -> Phase B run produces a populated
EvidenceModel (real artifacts, non-empty attestations, digest-based identity)
verifiable via ``GET /runs/{run_id}/report?view=compliance``, plus the
exception grant -> waive -> revoke -> fail-again demonstration.

OPA is live (docker-compose); the runner adapter is mocked per the batch's
"full mocked Phase A -> Phase B run" DoD.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from tests.unit.test_orchestrator.test_phase_b_orchestrator import (
    DIGEST,
    _happy_downloader,
    _phase_b_spec_document,
)
from tests.unit.test_projects.test_project_registry import INTAKE_SCHEMA, _answers

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.audit.audit_store import AuditStore
from ci_agent.config.settings import Settings
from ci_agent.core.models.common import PolicyDecision, StageStatus
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.exceptions.exception_service import ExceptionService
from ci_agent.exceptions.models import utcnow
from ci_agent.governance import load_policy_spec
from ci_agent.ingress.app import create_app
from ci_agent.orchestrator.phase_a_orchestrator import PhaseAOrchestrator
from ci_agent.orchestrator.phase_b_orchestrator import PhaseBOrchestrator
from ci_agent.planner.planner import Planner
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.policy.opa_client import OPAClient
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard
from ci_agent.supplychain.sbom_service import SBOMService
from ci_agent.supplychain.signing_service import SigningService, VerifyRunner

REPO = "example-org/payments-api"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def _opa_up() -> bool:
    try:
        return httpx.get("http://127.0.0.1:8181/health", timeout=2.0).status_code == 200
    except httpx.TransportError:
        return False


requires_opa = pytest.mark.skipif(not _opa_up(), reason="requires live OPA")


class _FakeAdapter:
    def __init__(self) -> None:
        self.compiled: list[Any] = []
        self.dispatches: list[str] = []

    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> CompiledArtifact:
        self.compiled.append(plan)
        return CompiledArtifact(
            kind="github_actions_workflow",
            content="name: fake",
            content_hash="x",
            metadata=metadata or {},
        )

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        self.dispatches.append(run_id)
        return DispatchRef(
            run_id=run_id,
            repository=artifact.metadata["repository"],
            branch=f"ci-agent/{run_id}",
            external_run_id="9001",
        )


class _FakeGitHub:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def post_check_run(self, repository: str, sha: str, **kwargs: Any) -> dict[str, Any]:
        self.checks.append({"repository": repository, "sha": sha, **kwargs})
        return {"id": len(self.checks)}


class _AlwaysVerify(VerifyRunner):
    def __init__(self, verified: bool) -> None:
        super().__init__("cosign")
        self._verified = verified

    @property
    def binary_path(self) -> str:
        return "/usr/bin/cosign"

    def run(self, args):  # type: ignore[override]
        from ci_agent.supplychain.signing_service import CommandResult

        return CommandResult(0 if self._verified else 1, "", "")


def _onboard(registry: ProjectRegistry) -> None:
    """Register the project; risk tier LOW so no human approval blocks the
    auto-approve path under test (mirrors the Batch 6 flow harness)."""
    from ci_agent.db.models import ProjectProfileRecord

    registry.register_project(
        intake_answers=_answers(), intake_schema=INTAKE_SCHEMA, repository=REPO
    )
    with registry._session_factory() as session:
        record = session.get(ProjectProfileRecord, REPO)
        stored = json.loads(record.profile_json)
        stored["risk_tier"] = "low"
        record.profile_json = json.dumps(stored)
        record.risk_tier = "low"
        session.commit()
    registry.register_pipeline_spec(REPO, _phase_b_spec_document())


@requires_opa
def test_full_mocked_phase_a_phase_b_run_populates_compliance_report(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'e2e.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    registry = ProjectRegistry(session_factory)
    _onboard(registry)
    policy_spec = load_policy_spec(local_dev_override=True)
    planner = Planner(TemplateRegistry(), policy_spec)
    exceptions = ExceptionService(session_factory, audit_store)
    pdp = PolicyDecisionPoint(
        OPAClient("http://127.0.0.1:8181", 2.0),
        audit_store,
        policy_spec,
        session_factory=session_factory,
        exception_service=exceptions,
    )
    adapter = _FakeAdapter()
    github = _FakeGitHub()
    sbom_service = SBOMService(session_factory, audit_store)
    signing_service = SigningService(
        session_factory, audit_store, sbom_service, verify_runner=_AlwaysVerify(True)
    )

    phase_a = PhaseAOrchestrator(
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
    phase_b = PhaseBOrchestrator(
        audit_store=audit_store,
        session_factory=session_factory,
        project_registry=registry,
        planner=planner,
        pdp=pdp,
        adapter=adapter,  # type: ignore[arg-type]
        github_client=github,  # type: ignore[arg-type]
        concurrency_guard=ConcurrencyGuard(3),
        policy_spec_version=policy_spec.policy_version,
        sbom_service=sbom_service,
        signing_service=signing_service,
        exception_service=exceptions,
        evidence_downloader=_happy_downloader,
    )
    phase_a.on_phase_a_approved = phase_b.start  # the create_app seam

    # --- Phase A ------------------------------------------------------------
    audit_store.create_run(
        run_id="run-e2e-b7",
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )
    from ci_agent.observer.execution_observer import ExecutionObserver

    observer = ExecutionObserver(session_factory, audit_store)
    phase_a.advance("run-e2e-b7", {"type": "run_created"})
    for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
        observer.record_stage_transition("run-e2e-b7", stage, StageStatus.PASSED)
        phase_a.on_stage_transition("run-e2e-b7", stage, "passed")
    observer.record_stage_transition("run-e2e-b7", "dependency_scan", StageStatus.PASSED)
    result = phase_a.on_stage_transition("run-e2e-b7", "dependency_scan", "passed")
    assert result is not None
    assert result["state"] == "merge_decision_published"
    assert result["approved"] is True

    # The Phase A approval triggered Phase B wave 1 automatically (the seam).
    assert len(adapter.dispatches) == 2

    # --- Phase B ------------------------------------------------------------
    for stage, coverage in (
        ("full_build", None),
        ("integration_tests", None),
        ("coverage_gate", 87.5),
        ("container_build", None),
        ("sbom_generate", None),
        ("image_scan", None),
        ("sign_attest", None),
    ):
        phase_b.on_stage_transition("run-e2e-b7", stage, "passed", coverage_percent=coverage)
    assert len(adapter.dispatches) == 3  # wave 2 dispatched after the gate
    phase_b.on_stage_transition("run-e2e-b7", "publish", "passed")
    final = phase_b.on_stage_transition("run-e2e-b7", "record_evidence", "passed")
    assert final == {"state": "evidence_recorded"}

    # --- The compliance report shows the real supply chain ------------------
    database_path = f"sqlite:///{tmp_path / 'e2e.db'}"
    settings = Settings(env="local", database_url=database_path)
    application = create_app(settings)
    with TestClient(application) as client:
        response = client.get("/runs/run-e2e-b7/report?view=compliance")
    assert response.status_code == 200
    package = response.json()
    evidence = package["evidence"]
    assert evidence["artifacts"], "compliance evidence must carry REAL artifacts"
    artifact = evidence["artifacts"][0]
    assert artifact["digest"] == DIGEST
    assert artifact["registry"] == "ghcr.io"  # registry host (allowlist scope)
    assert artifact["sbom_ref"]
    assert artifact["signature_ref"] == "image.sig"
    assert evidence["attestations"]
    # Sample (report-back artifact): print a compact slice.
    print(
        "COMPLIANCE_EVIDENCE_SAMPLE="
        + json.dumps(
            {
                "digest": artifact["digest"],
                "registry": artifact["registry"],
                "sbom_ref": artifact["sbom_ref"][:60] + "...",
                "signature_ref": artifact["signature_ref"],
                "attestations": evidence["attestations"],
            },
            indent=1,
        )
    )
    # The publish gate decision is on record with artifact facts evaluated.
    decisions = package["policy_decisions"]
    publish = [d for d in decisions if d["stage_id"] == "publish_gate"]
    assert publish and publish[-1]["decision"] == "pass"


@requires_opa
def test_exception_grant_waive_revoke_fail_again_demonstration(tmp_path) -> None:
    """Section 18 demonstration: violation -> waived by governed exception ->
    revoked -> fails again. Scripted before/after output printed for the
    batch report."""
    engine = create_engine(f"sqlite:///{tmp_path / 'waive-e2e.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    audit_store.create_run(
        run_id="run-waive-demo",
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )
    policy_spec = load_policy_spec()
    exceptions = ExceptionService(session_factory, audit_store)
    pdp = PolicyDecisionPoint(
        OPAClient("http://127.0.0.1:8181", 2.0),
        audit_store,
        policy_spec,
        session_factory=session_factory,
        exception_service=exceptions,
    )
    from ci_agent.policy.models import PolicyInputFacts

    def gate() -> PolicyDecision:
        facts = PolicyInputFacts(
            project_profile={"risk_tier": "low"},
            pipeline_spec={"project_id": REPO},
            stage_id="security_gate",
            findings=[
                {
                    "severity": "high",
                    "scanner": "trivy",
                    "rule_id": "CVE-2023-0286",
                    "component": "libssl3@3.0.11",
                    "disposition": "open",
                }
            ],
            run_id="run-waive-demo",
        )
        return pdp.evaluate_gate("security_gate", facts)

    lines: list[str] = []

    before = gate()
    lines.append(f"BEFORE grant : decision={before.decision.value}")
    assert before.decision is PolicyDecision.FAIL

    record = exceptions.grant_exception(
        project_id=REPO,
        policy_family="security_policy",
        rule_id="CVE-2023-0286",
        reason="fix scheduled for the next sprint; risk accepted by security-lead",
        granted_by="security-lead",
        expires_at=utcnow() + timedelta(days=7),
    )
    waived = gate()
    lines.append(
        f"AFTER grant  : decision={waived.decision.value} "
        f"exception_ids={waived.exception_ids} (granted_by=security-lead, "
        f"expires_at={record.expires_at.isoformat()}Z)"
    )
    assert waived.decision is PolicyDecision.WAIVED
    assert waived.exception_ids == [record.id]

    exceptions.revoke_exception(record.id, revoked_by="security-council")
    after = gate()
    lines.append(f"AFTER revoke : decision={after.decision.value}")
    assert after.decision is PolicyDecision.FAIL

    print("EXCEPTION_DEMONSTRATION=\n".join([""]) + "\n".join(lines))
