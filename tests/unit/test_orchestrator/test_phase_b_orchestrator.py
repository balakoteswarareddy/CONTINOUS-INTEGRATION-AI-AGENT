"""Phase B orchestrator tests (Batch 7, Task E; Report Sections 5.2, 8, 10).

Covers the batch DoD:
* full happy-path Phase B run (mocked adapter/tool outputs) ending in
  EVIDENCE_RECORDED with a POPULATED EvidenceModel (real artifact digest,
  SBOM reference, signature + provenance attestations);
* Phase B does NOT trigger on a failed/rejected Phase A (enforced, tested);
* coverage gate fail-closed behaviour;
* publish gate blocks wave 2 when signing is required-but-unverifiable or
  when REAL image findings exceed thresholds (live OPA);
* a WAIVED publish gate dispatches wave 2 and records the exception ids.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.unit.test_projects.test_project_registry import INTAKE_SCHEMA, _answers

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.db.models import ArtifactRecord, RunRecord
from ci_agent.exceptions.exception_service import ExceptionService
from ci_agent.governance import load_policy_spec
from ci_agent.orchestrator.phase_b_orchestrator import PhaseBOrchestrator
from ci_agent.planner.planner import Planner
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.policy.models import PolicyDecisionResult, PolicyInputFacts
from ci_agent.policy.opa_client import OPAClient
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard
from ci_agent.reporting.evidence_assembler import EvidenceAssembler
from ci_agent.security.security_evidence_service import SecurityEvidenceService
from ci_agent.supplychain.sbom_service import SBOMService
from ci_agent.supplychain.signing_service import SigningService, VerifyRunner

REPO = "example-org/payments-api"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

DIGEST = "sha256:" + "7c" * 32

SIGN_BUNDLE = json.dumps(
    {"signature_ref": "image.sig", "bundle_ref": "image.bundle", "keyless": False}
)


def _phase_b_spec_document() -> dict[str, Any]:
    from ci_agent.core.models.common import EventType
    from ci_agent.core.models.pipeline_spec import PipelineSpec

    spec = PipelineSpec(
        project_id=REPO,
        project_name="Payments API",
        stack={"language": "python"},
        repository={"provider": "github", "url": f"https://github.com/{REPO}", "repo_id": REPO},
        trigger={"event_type": EventType.PUSH, "branch": "main", "source_sha": "cafe1234"},
        stages=[
            {"id": "checkout", "name": "Checkout", "depends_on": []},
            {"id": "format_lint", "name": "Lint", "depends_on": ["checkout"]},
            {"id": "sast", "name": "SAST", "depends_on": ["format_lint"]},
            {"id": "unit_tests", "name": "Unit tests", "depends_on": ["format_lint"]},
            {"id": "secret_scan", "name": "Secret scan", "depends_on": ["sast"]},
            {"id": "dependency_scan", "name": "SCA", "depends_on": ["sast"]},
            {
                "id": "policy_gate",
                "name": "Policy gate",
                "depends_on": ["unit_tests", "secret_scan", "dependency_scan"],
            },
            {"id": "human_approval", "name": "Approval", "depends_on": ["policy_gate"]},
            {"id": "merge_decision", "name": "Merge decision", "depends_on": ["human_approval"]},
            {"id": "full_build", "name": "Full build", "depends_on": ["merge_decision"]},
            {"id": "integration_tests", "name": "Integration tests", "depends_on": ["full_build"]},
            {"id": "coverage_gate", "name": "Coverage gate", "depends_on": ["integration_tests"]},
            {
                "id": "container_build",
                "name": "Container build",
                "depends_on": ["coverage_gate"],
                "base_image": "python:3.11-slim",
            },
            {"id": "sbom_generate", "name": "SBOM", "depends_on": ["container_build"]},
            {"id": "image_scan", "name": "Image scan", "depends_on": ["sbom_generate"]},
            {"id": "sign_attest", "name": "Sign & attest", "depends_on": ["image_scan"]},
            {"id": "publish", "name": "Publish", "depends_on": ["sign_attest"]},
            {"id": "record_evidence", "name": "Record evidence", "depends_on": ["publish"]},
        ],
        thresholds={"coverage_percent": 80},
        approvals_required=False,
        artifact_destinations=["ghcr.io/example-org/payments-api"],
        policy_version="1.0.0",
    )
    return spec.model_dump(mode="json")


class _StubPDP:
    """Scripted PDP for orchestrator flow tests (unit only)."""

    def __init__(self, publish_decision: PolicyDecision = PolicyDecision.PASS) -> None:
        self.publish_decision = publish_decision
        self.publish_calls: list[PolicyInputFacts] = []

    def evaluate_gate(self, stage_id: str, facts: PolicyInputFacts) -> PolicyDecisionResult:
        if stage_id == "plan_approval":
            return PolicyDecisionResult(
                decision=PolicyDecision.PASS,
                policy_family="aggregated",
                policy_version="1.0.0",
            )
        assert stage_id == "publish_gate", stage_id
        self.publish_calls.append(facts)
        reasons: list[str] = []
        if self.publish_decision is PolicyDecision.FAIL:
            reasons = ["artifact_policy: artifact is not signed"]
        return PolicyDecisionResult(
            decision=self.publish_decision,
            reasons=reasons,
            policy_family="aggregated",
            policy_version="1.0.0",
            exception_ids=(["exc-test"] if self.publish_decision is PolicyDecision.WAIVED else []),
        )

    @property
    def policy_version(self) -> str:
        return "1.0.0"


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
            run_id=run_id, repository=artifact.metadata["repository"], branch=f"ci-agent/{run_id}"
        )


class _FakeGitHub:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def post_check_run(self, repository: str, sha: str, **kwargs: Any) -> dict[str, Any]:
        self.checks.append({"repository": repository, "sha": sha, **kwargs})
        return {"id": len(self.checks)}


class _AlwaysVerify(VerifyRunner):
    """Test double standing in for a working cosign installation."""

    def __init__(self, verified: bool) -> None:
        super().__init__("cosign")
        self._verified = verified

    @property
    def binary_path(self) -> str:
        return "/usr/bin/cosign"  # pretend installed

    def run(self, args):  # type: ignore[override]
        from ci_agent.supplychain.signing_service import CommandResult

        return CommandResult(
            0 if self._verified else 1, "", "" if self._verified else "bad signature"
        )


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'b7.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    registry = ProjectRegistry(session_factory)
    registry.register_project(
        intake_answers=_answers(), intake_schema=INTAKE_SCHEMA, repository=REPO
    )
    registry.register_pipeline_spec(REPO, _phase_b_spec_document())
    policy_spec = load_policy_spec()
    planner = Planner(TemplateRegistry(), policy_spec)
    pdp = _StubPDP()
    adapter = _FakeAdapter()
    github = _FakeGitHub()
    sbom_service = SBOMService(session_factory, audit_store)
    signing_service = SigningService(
        session_factory, audit_store, sbom_service, verify_runner=_AlwaysVerify(True)
    )
    exceptions = ExceptionService(session_factory, audit_store)
    guard = ConcurrencyGuard(3)

    def make_orchestrator(
        *,
        pdp_override: Any | None = None,
        signing_override: SigningService | None = None,
        downloader: Any | None = None,
    ) -> PhaseBOrchestrator:
        return PhaseBOrchestrator(
            audit_store=audit_store,
            session_factory=session_factory,
            project_registry=registry,
            planner=planner,
            pdp=pdp_override or pdp,
            adapter=adapter,  # type: ignore[arg-type]
            github_client=github,  # type: ignore[arg-type]
            concurrency_guard=guard,
            policy_spec_version=policy_spec.policy_version,
            sbom_service=sbom_service,
            signing_service=signing_override or signing_service,
            exception_service=exceptions,
            evidence_downloader=downloader,
        )

    return {
        "session_factory": session_factory,
        "audit_store": audit_store,
        "registry": registry,
        "policy_spec": policy_spec,
        "adapter": adapter,
        "github": github,
        "sbom_service": sbom_service,
        "signing_service": signing_service,
        "exceptions": exceptions,
        "pdp": pdp,
        "make_orchestrator": make_orchestrator,
    }


def _approve_phase_a(env: dict, run_id: str, *, approved: bool = True) -> None:
    """Simulate a COMPLETED Phase A: state + audited merge decision."""
    session_factory = env["session_factory"]
    audit_store = env["audit_store"]
    audit_store.create_run(
        run_id=run_id,
        project_id=REPO,
        repository=REPO,
        trigger_type="push",
        source_sha="cafe1234",
    )
    with session_factory() as session:
        run = session.get(RunRecord, run_id)
        run.current_state = "merge_decision_published"
        session.commit()
    audit_store.append_event(run_id, "merge_decision_published", {"approved": approved})


def _happy_downloader(run_id: str, stage_id: str) -> dict[str, str]:
    if stage_id == "container_build":
        return {"image-digest.txt": DIGEST + "\n"}
    if stage_id == "sbom_generate":
        return {"sbom.json": (FIXTURES / "sbom" / "syft_spdx.json").read_text(encoding="utf-8")}
    if stage_id == "sign_attest":
        return {
            "image.sig": SIGN_BUNDLE,
            "image-attestation.json": json.dumps(
                {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [{"name": "ci-agent/app", "digest": {"sha256": "7c" * 32}}],
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "predicate": {"builder": {"id": "ci-agent"}},
                }
            ),
        }
    return {}


def _drive_wave_1(orch: PhaseBOrchestrator, run_id: str) -> dict[str, Any] | None:
    result: dict[str, Any] | None = None
    for stage, coverage in (
        ("full_build", None),
        ("integration_tests", None),
        ("coverage_gate", 87.0),
        ("container_build", None),
        ("sbom_generate", None),
        ("image_scan", None),
        ("sign_attest", None),
    ):
        result = orch.on_stage_transition(run_id, stage, "passed", coverage_percent=coverage)
    return result


class TestHappyPath:
    def test_full_phase_b_run_records_evidence(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-happy-1")

        start = orchestrator.start("run-happy-1")
        assert start == {"state": "merge_decision_published", "phase_b": "dispatched", "wave": 1}
        # Wave 1 compiled exactly the seven pre-publish stages.
        wave_1_stages = [s.stage_id for s in env["adapter"].compiled[0].resolved_steps]
        assert wave_1_stages[0] == "full_build"
        assert wave_1_stages[-1] == "sign_attest"

        result = _drive_wave_1(orchestrator, "run-happy-1")
        assert result is not None
        assert result["state"] == "signed"
        assert result["phase_b"] == "wave-2 dispatched"
        # Wave 2 (publish + record_evidence) dispatched ONLY after the gate.
        wave_2_stages = [s.stage_id for s in env["adapter"].compiled[1].resolved_steps]
        assert wave_2_stages == ["publish", "record_evidence"]

        assert orchestrator.on_stage_transition("run-happy-1", "publish", "passed") == {
            "state": "published"
        }
        final = orchestrator.on_stage_transition("run-happy-1", "record_evidence", "passed")
        assert final == {"state": "evidence_recorded"}

        # --- The Batch-1-era promise finally kept: populated EvidenceModel ---
        assembler = EvidenceAssembler(env["session_factory"], env["audit_store"])
        evidence = assembler.assemble_evidence("run-happy-1")
        assert evidence.artifacts, "artifacts must be populated for real"
        artifact = evidence.artifacts[0]
        assert artifact.digest == DIGEST  # immutable digest identity
        assert artifact.registry == "ghcr.io"  # registry HOST (allowlist scope)
        assert artifact.sbom_ref and "spdx" not in artifact.digest
        assert artifact.signature_ref == "image.sig"
        assert evidence.attestations, "attestations must be populated for real"
        assert any(a.startswith("cosign-signature:") for a in evidence.attestations)
        assert any("slsa.dev/provenance" in a for a in evidence.attestations)

    def test_digest_recorded_from_build_output_never_tag(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-happy-2")
        orchestrator.start("run-happy-2")
        for stage, coverage in (
            ("full_build", None),
            ("integration_tests", None),
            ("coverage_gate", 90.0),
            ("container_build", None),
        ):
            orchestrator.on_stage_transition(
                "run-happy-2", stage, "passed", coverage_percent=coverage
            )
        with env["session_factory"]() as session:
            record = session.query(ArtifactRecord).filter_by(run_id="run-happy-2").one()
            assert record.digest == DIGEST


class TestTriggerDiscipline:
    def test_phase_b_never_runs_against_failed_phase_a(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        env["audit_store"].create_run(
            run_id="run-failed-a",
            project_id=REPO,
            repository=REPO,
            trigger_type="push",
            source_sha="cafe1234",
        )
        with env["session_factory"]() as session:
            run = session.get(RunRecord, "run-failed-a")
            run.current_state = "failed"
            session.commit()
        from ci_agent.orchestrator.phase_a_orchestrator import CallerError

        with pytest.raises(CallerError, match="approved merge decision"):
            orchestrator.start("run-failed-a")
        # State untouched; the block is audited.
        with env["session_factory"]() as session:
            assert session.get(RunRecord, "run-failed-a").current_state == "failed"
        events = [e.event_type for e in env["audit_store"].get_audit_trail("run-failed-a")]
        assert "phase_b_blocked" in events
        assert env["adapter"].dispatches == []

    def test_phase_b_never_runs_on_rejected_merge_decision(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-rejected-a", approved=False)
        from ci_agent.orchestrator.phase_a_orchestrator import CallerError

        with pytest.raises(CallerError, match="APPROVED"):
            orchestrator.start("run-rejected-a")
        assert env["adapter"].dispatches == []


class TestCoverageGate:
    def test_missing_coverage_with_configured_threshold_fails_closed(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-cov-1")
        orchestrator.start("run-cov-1")
        orchestrator.on_stage_transition("run-cov-1", "full_build", "passed")
        orchestrator.on_stage_transition("run-cov-1", "integration_tests", "passed")
        result = orchestrator.on_stage_transition(
            "run-cov-1", "coverage_gate", "passed", coverage_percent=None
        )
        assert result == {
            "state": "failed",
            "reason": (
                "coverage gate: no coverage_percent in structured output but a "
                "coverage_percent threshold (80) is configured — fail closed"
            ),
        }

    def test_below_threshold_coverage_fails(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-cov-2")
        orchestrator.start("run-cov-2")
        orchestrator.on_stage_transition("run-cov-2", "full_build", "passed")
        orchestrator.on_stage_transition("run-cov-2", "integration_tests", "passed")
        result = orchestrator.on_stage_transition(
            "run-cov-2", "coverage_gate", "passed", coverage_percent=61.5
        )
        assert result is not None
        assert result["state"] == "failed"
        assert "61.5% is below" in result["reason"]

    def test_no_threshold_configured_passes_without_coverage(self, env) -> None:
        # Remove the threshold from the registered spec.
        spec = _phase_b_spec_document()
        spec["thresholds"] = {}
        env["registry"].register_pipeline_spec(REPO, spec)
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-cov-3")
        orchestrator.start("run-cov-3")
        orchestrator.on_stage_transition("run-cov-3", "full_build", "passed")
        orchestrator.on_stage_transition("run-cov-3", "integration_tests", "passed")
        result = orchestrator.on_stage_transition("run-cov-3", "coverage_gate", "passed")
        assert result == {"state": "coverage_checked"}


class TestPublishGateEnforcement:
    def test_missing_signing_evidence_fails_closed_before_gate(self, env) -> None:
        """sign_attest passed but produced NOTHING: run parks in ERROR —
        the publish job is never even considered."""
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-nosig")

        def no_signature(run_id: str, stage_id: str) -> dict[str, str]:
            if stage_id == "sign_attest":
                return {}  # artifact upload missing
            return _happy_downloader(run_id, stage_id)

        orchestrator._evidence_downloader = no_signature
        orchestrator.start("run-nosig")
        for stage, coverage in (
            ("full_build", None),
            ("integration_tests", None),
            ("coverage_gate", 91.0),
            ("container_build", None),
            ("sbom_generate", None),
            ("image_scan", None),
        ):
            orchestrator.on_stage_transition(
                "run-nosig", stage, "passed", coverage_percent=coverage
            )
        from ci_agent.orchestrator.phase_a_orchestrator import OrchestrationError

        with pytest.raises(OrchestrationError):
            orchestrator.on_stage_transition("run-nosig", "sign_attest", "passed")
        with env["session_factory"]() as session:
            assert session.get(RunRecord, "run-nosig").current_state == "error"
        assert len(env["adapter"].dispatches) == 1  # wave 2 never dispatched

    def test_unverifiable_signature_blocks_publish_with_live_opa(self, env) -> None:
        """Signing required by policy; the recorded signature FAILS real
        verification -> artifact_policy rejects -> run FAILED, no wave 2."""
        policy_spec = load_policy_spec()
        real_pdp = PolicyDecisionPoint(
            OPAClient("http://127.0.0.1:8181", 2.0),
            env["audit_store"],
            policy_spec,
            session_factory=env["session_factory"],
            exception_service=env["exceptions"],
        )
        bad_verify = SigningService(
            env["session_factory"],
            env["audit_store"],
            env["sbom_service"],
            verify_runner=_AlwaysVerify(False),
        )
        orchestrator = env["make_orchestrator"](
            pdp_override=real_pdp, signing_override=bad_verify, downloader=_happy_downloader
        )
        _approve_phase_a(env, "run-badsig")
        orchestrator.start("run-badsig")
        result = _drive_wave_1(orchestrator, "run-badsig")
        assert result is not None
        assert result["state"] == "failed"
        assert result["reason"] == "publish_gate rejected"
        # The rego's reason: the recorded signature did NOT verify.
        from ci_agent.db.models import PolicyDecisionRecord

        with env["session_factory"]() as session:
            row = (
                session.query(PolicyDecisionRecord)
                .filter_by(run_id="run-badsig", stage_id="publish_gate")
                .order_by(PolicyDecisionRecord.id.desc())
                .first()
            )
            assert row is not None
            assert any("not signed" in r for r in json.loads(row.reasons_json))
        assert len(env["adapter"].dispatches) == 1  # wave 2 never dispatched

    def test_image_scan_findings_block_publish_with_live_opa(self, env) -> None:
        """Real Trivy HIGH finding on the image -> security_policy blocks."""
        policy_spec = load_policy_spec()
        real_pdp = PolicyDecisionPoint(
            OPAClient("http://127.0.0.1:8181", 2.0),
            env["audit_store"],
            policy_spec,
            session_factory=env["session_factory"],
            exception_service=env["exceptions"],
        )
        orchestrator = env["make_orchestrator"](pdp_override=real_pdp, downloader=_happy_downloader)
        _approve_phase_a(env, "run-vuln")
        # A real parsed HIGH trivy finding exists for this run (Batch 6 flow).
        evidence = SecurityEvidenceService(env["session_factory"], env["audit_store"])
        evidence.collect_findings(
            "run-vuln",
            "image_scan",
            "trivy",
            (FIXTURES / "security_tool_outputs" / "trivy_with_vuln.json").read_text(
                encoding="utf-8"
            ),
        )
        orchestrator.start("run-vuln")
        result = _drive_wave_1(orchestrator, "run-vuln")
        assert result is not None
        assert result["state"] == "failed"
        assert len(env["adapter"].dispatches) == 1

    def test_waived_publish_gate_dispatches_wave_2_and_records_ids(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        env["pdp"].publish_decision = PolicyDecision.WAIVED
        _approve_phase_a(env, "run-waived-b")
        orchestrator.start("run-waived-b")
        result = _drive_wave_1(orchestrator, "run-waived-b")
        assert result is not None
        assert result["phase_b"] == "wave-2 dispatched"
        assert result["exception_ids"] == ["exc-test"]
        assert len(env["adapter"].dispatches) == 2
        events = [
            json.loads(e.payload_json)
            for e in env["audit_store"].get_audit_trail("run-waived-b")
            if e.event_type == "phase_b_dispatched"
        ]
        assert events[-1]["exception_ids"] == ["exc-test"]
        assert "waived by exception" in events[-1]["note"]


class TestEvidenceCollectionFailures:
    def test_missing_digest_fails_closed(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-nodigest")

        def no_digest(run_id: str, stage_id: str) -> dict[str, str]:
            if stage_id == "container_build":
                return {"image-digest.txt": ""}
            return _happy_downloader(run_id, stage_id)

        orchestrator._evidence_downloader = no_digest
        orchestrator.start("run-nodigest")
        orchestrator.on_stage_transition("run-nodigest", "full_build", "passed")
        orchestrator.on_stage_transition("run-nodigest", "integration_tests", "passed")
        orchestrator.on_stage_transition(
            "run-nodigest", "coverage_gate", "passed", coverage_percent=95.0
        )
        from ci_agent.orchestrator.phase_a_orchestrator import OrchestrationError

        with pytest.raises(OrchestrationError):
            orchestrator.on_stage_transition("run-nodigest", "container_build", "passed")
        with env["session_factory"]() as session:
            assert session.get(RunRecord, "run-nodigest").current_state == "error"

    def test_malformed_sbom_fails_closed(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-badsbom")

        def bad_sbom(run_id: str, stage_id: str) -> dict[str, str]:
            if stage_id == "sbom_generate":
                return {"sbom.json": "{not an sbom"}
            return _happy_downloader(run_id, stage_id)

        orchestrator._evidence_downloader = bad_sbom
        orchestrator.start("run-badsbom")
        for stage, coverage in (
            ("full_build", None),
            ("integration_tests", None),
            ("coverage_gate", 95.0),
            ("container_build", None),
        ):
            orchestrator.on_stage_transition(
                "run-badsbom", stage, "passed", coverage_percent=coverage
            )
        from ci_agent.orchestrator.phase_a_orchestrator import OrchestrationError

        with pytest.raises(OrchestrationError):
            orchestrator.on_stage_transition("run-badsbom", "sbom_generate", "passed")
        with env["session_factory"]() as session:
            assert session.get(RunRecord, "run-badsbom").current_state == "error"


class TestPhaseATriggerWiring:
    def test_phase_a_approved_callback_starts_phase_b(self, env) -> None:
        """The seam wired in create_app: Phase A approval -> Phase B start."""

        calls: list[str] = []
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)

        # Simulate Phase A's post-approval hook invocation shape.
        def on_approved(run_id: str) -> None:
            calls.append(run_id)
            orchestrator.start(run_id)

        _approve_phase_a(env, "run-seam")
        on_approved("run-seam")
        assert calls == ["run-seam"]
        assert env["adapter"].dispatches == ["run-seam"]
