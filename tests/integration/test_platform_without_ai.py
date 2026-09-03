"""Batch 9 integration proof: the platform runs end to end WITHOUT any AI
(Report Section 18 non-negotiable: "the platform remains functional when
the AI service is unavailable"; Section 12 "internal/no-model fallback").

What is REAL here: the whole ``create_app`` wiring — ingress API, admin API,
project registry, audit store, planner, AI gateway + all four AI features,
report/evidence assembly — all against one SQLite database, with the DEFAULT
``AI_PROVIDER=noop`` (no API key configured anywhere).

What is FAKED and why: only the Policy Decision Point (an in-process
pass-through standing in for the OPA-backed PDP). This sandbox has no live
OPA, so the Batch 5/7 live-OPA integration tests skip here; faking ONLY the
PDP keeps this proof runnable everywhere while every other singleton stays
production wiring. (Documented in NOTES.md, Batch 9 section.)

Proves, in order:

1. onboarding through the real admin API succeeds while the AI normalizer
   runs in noop fallback (advisory, answers unchanged);
2. a full Phase A run reaches ``merge_decision_published`` with ZERO AI
   participation in the control path;
3. the three AI endpoints answer over the real app — deterministic
   fallbacks, never errors;
4. every AI invocation (register + triage + summarize + explain) is logged
   as an ``AIInvocationRecord`` carrying sha256 hashes ONLY — a byte-level
   scan of the database file proves no prompt or response text persists;
5. the run's audit hash chain still verifies.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from tests.unit.test_projects.test_project_registry import _answers, _spec_document

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.config.settings import Settings
from ci_agent.core.models.common import PolicyDecision, StageStatus
from ci_agent.db.models import AIInvocationRecord, ProjectProfileRecord
from ci_agent.governance import load_policy_spec
from ci_agent.ingress.app import create_app
from ci_agent.observer.execution_observer import ExecutionObserver
from ci_agent.orchestrator.phase_a_orchestrator import PhaseAOrchestrator
from ci_agent.planner.planner import Planner
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.policy.models import PolicyDecisionResult
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard

pytestmark = pytest.mark.integration

REPO = "example-org/payments-api"
ADMIN_KEY = "test-admin-key"
AUTH = {"X-Admin-Key": ADMIN_KEY}
RUN_ID = "run-noai"
SHA256_HEX = re.compile(r"sha256:[0-9a-f]{64}")

# A snippet with a recognizable fingerprint: it enters a triage prompt, so
# its absence from the database file bytes proves prompts are never stored.
TRIAGE_SNIPPET = "pytest: FAILED test_charge - AssertionError (fingerprint-noai-7734)"
SYSTEM_FRAMING_FRAGMENT = b"You are a CI pipeline assistant"


class _FakeAdapter:
    """Records dispatches; returns a well-formed DispatchRef."""

    def __init__(self) -> None:
        self.dispatches: list[str] = []

    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> CompiledArtifact:
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

    def post_check_run(self, repository: str, sha: str, **kwargs: Any) -> dict[str, int]:
        self.checks.append({**kwargs})
        return {"id": len(self.checks)}


class _FakePDP:
    """In-process pass-through PDP (the ONLY fake singleton in this test)."""

    def __init__(self, policy_version: str = "9.9.9-test") -> None:
        self._policy_version = policy_version
        self.gates_evaluated: list[str] = []

    def evaluate_gate(self, stage_id: str, facts: Any) -> PolicyDecisionResult:
        self.gates_evaluated.append(stage_id)
        return PolicyDecisionResult(
            decision=PolicyDecision.PASS,
            reasons=[],
            policy_family="all",
            policy_version=self._policy_version,
        )


def _invocations(client: TestClient) -> list[AIInvocationRecord]:
    with client.app.state.session_factory() as session:
        return list(session.execute(select(AIInvocationRecord)).scalars().all())


def test_full_phase_a_and_ai_features_with_zero_ai_configured(tmp_path: Path) -> None:
    settings = Settings(
        env="local",
        database_url=f"sqlite:///{tmp_path / 'noai.db'}",
        admin_api_key=ADMIN_KEY,
    )
    application = create_app(settings)

    # Section 12/18: default deployment registers NO model provider.
    assert application.state.model_gateway.provider_names == []

    with TestClient(application) as client:
        # ------------------------------------------------ 1. onboarding (real API)
        response = client.post(
            "/admin/projects",
            json={"intake_answers": _answers(), "repository": REPO},
            headers=AUTH,
        )
        assert response.status_code == 201, response.text
        assert response.json()["project_id"] == REPO

        # The registration above already exercised the AI normalizer hook
        # (noop fallback: answers unchanged, registration unaffected). That
        # is the ONLY AI invocation so far — the control path itself is AI-free.
        records = _invocations(client)
        assert len(records) == 1
        assert records[0].feature == "requirement_normalization"
        assert records[0].provider == "noop"

        # Force LOW risk tier (established integration-test pattern) so the
        # run auto-approves instead of waiting on human approval.
        with client.app.state.session_factory() as session:
            record = session.get(ProjectProfileRecord, REPO)
            stored = json.loads(record.profile_json)
            stored["risk_tier"] = "low"
            record.profile_json = json.dumps(stored)
            record.risk_tier = "low"
            session.commit()
        client.app.state.project_registry.register_pipeline_spec(REPO, _spec_document())

        # --------------------------------------- 2. Phase A to terminal, zero AI
        policy_spec = load_policy_spec(local_dev_override=True)
        phase_a = PhaseAOrchestrator(
            audit_store=client.app.state.audit_store,
            session_factory=client.app.state.session_factory,
            project_registry=client.app.state.project_registry,
            planner=Planner(TemplateRegistry(), policy_spec),
            pdp=_FakePDP(policy_spec.policy_version),
            adapter=_FakeAdapter(),  # type: ignore[arg-type]
            github_client=_FakeGitHub(),  # type: ignore[arg-type]
            concurrency_guard=ConcurrencyGuard(3),
            policy_spec_version=policy_spec.policy_version,
            require_human_approval_for=frozenset(
                policy_spec.approval_policy.require_human_approval_for
            ),
        )
        client.app.state.audit_store.create_run(
            run_id=RUN_ID,
            project_id=REPO,
            repository=REPO,
            trigger_type="push",
            source_sha="cafe1234",
        )
        observer = ExecutionObserver(client.app.state.session_factory, client.app.state.audit_store)
        phase_a.advance(RUN_ID, {"type": "run_created"})
        for stage in ("checkout", "format_lint", "sast", "unit_tests", "secret_scan"):
            observer.record_stage_transition(RUN_ID, stage, StageStatus.PASSED)
            phase_a.on_stage_transition(RUN_ID, stage, "passed")
        observer.record_stage_transition(RUN_ID, "dependency_scan", StageStatus.PASSED)
        result = phase_a.on_stage_transition(RUN_ID, "dependency_scan", "passed")

        assert result is not None
        assert result["state"] == "merge_decision_published"
        assert result["approved"] is True
        # Still exactly ONE AI invocation: the run itself used zero AI.
        assert len(_invocations(client)) == 1

        # --------------------------------- 3. AI features over the real endpoints
        triage = client.post(
            f"/runs/{RUN_ID}/triage/unit_tests",
            json={"logs_snippet": TRIAGE_SNIPPET},
            headers=AUTH,
        )
        assert triage.status_code == 200
        assert triage.json()["ai_assisted"] is False
        assert triage.json()["fallback_used"] is True
        assert triage.json()["remediation_hints"]  # deterministic guidance

        summarize = client.post(f"/runs/{RUN_ID}/summarize", headers=AUTH)
        assert summarize.status_code == 200
        summary_body = summarize.json()
        assert summary_body["ai_assisted"] is False
        assert summary_body["fallback_used"] is True
        assert RUN_ID in summary_body["executive_summary"]
        assert "pass" in summary_body["executive_summary"]

        explain = client.post("/pipeline-spec/explain", json={"spec": _spec_document()})
        assert explain.status_code == 200
        explain_body = explain.json()
        assert explain_body["ai_assisted"] is False
        assert explain_body["fallback_used"] is True
        assert explain_body["stage_summaries"]

        # ------------------- 4. every invocation logged; hashes only, never content
        records = _invocations(client)
        assert [r.feature for r in records] == [
            "requirement_normalization",
            "failure_triage",
            "report_summarization",
            "pipeline_explanation",
        ]
        for record in records:
            assert record.provider == "noop"
            assert SHA256_HEX.fullmatch(record.prompt_hash)
            assert SHA256_HEX.fullmatch(record.response_hash)
            # Deny-by-default committed policy: only public data may reach a
            # provider, and all four feature payloads classify as internal —
            # so every request was policy-rejected before the (empty) chain.
            assert record.policy_allowed is False
        trail = client.app.state.audit_store.get_audit_trail(RUN_ID)
        assert any(e.event_type == "ai_policy_rejected" for e in trail)

        # Byte-level proof: no prompt/response text anywhere in the database
        # (main file plus any journal/WAL sidecars).
        blob = b"".join(path.read_bytes() for path in sorted(tmp_path.glob("noai.db*")))
        assert SYSTEM_FRAMING_FRAGMENT not in blob
        assert TRIAGE_SNIPPET.encode() not in blob
        assert b"noop (deterministic fallback" not in blob  # response text absent too

        # ---------------------------------------------- 5. audit chain verifies
        assert client.app.state.audit_store.verify_chain(RUN_ID) is True
