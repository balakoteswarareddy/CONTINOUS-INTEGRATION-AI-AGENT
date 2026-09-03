"""Integration: PDP + Rego + Planner against a live OPA (Batch 3 DoD 2/3).

Requires OPA serving governance/rego at OPA_URL (default http://localhost:8181):

    docker-compose up opa
    # or, without Docker:
    opa run --server --set=decision_logs.console=true governance/rego

Skips gracefully with a clear message when OPA isn't running.
"""

from __future__ import annotations

import os

import httpx
import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.governance import load_policy_spec
from ci_agent.planner.planner import Planner
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.policy.models import PolicyInputFacts
from ci_agent.policy.opa_client import OPAClient
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint

pytestmark = pytest.mark.integration

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")


def _opa_running() -> bool:
    try:
        with httpx.Client(timeout=1.0) as client:
            return client.get(f"{OPA_URL}/health").status_code == 200
    except httpx.HTTPError:
        return False


requires_opa = pytest.mark.skipif(
    not _opa_running(), reason="OPA is not running (docker-compose up opa)"
)


@pytest.fixture()
def audit_store_integration(tmp_path) -> AuditStore:
    engine = create_engine(f"sqlite:///{tmp_path / 'pdp-integration.db'}")
    Base.metadata.create_all(engine)
    yield AuditStore(get_session_factory(engine))
    engine.dispose()


@pytest.fixture()
def live_pdp(audit_store_integration: AuditStore) -> PolicyDecisionPoint:
    """PDP against LIVE OPA with the GOVERNED catalog policy (not a fixture spec).

    Uses the local-dev identity override explicitly (Batch 5.1): the committed
    identity_policy.yaml is deny-everything, so these positive-path tests
    could not pass against it. Other families are the governed defaults.
    """
    client = OPAClient(base_url=OPA_URL)
    yield PolicyDecisionPoint(
        opa_client=client,
        audit_store=audit_store_integration,
        policy_spec=load_policy_spec(local_dev_override=True),
    )
    client.close()


def build_gate_facts(plan, profile, pipeline_spec, run_id="run-int-1", **overrides):
    payload = {
        "project_profile": profile.model_dump(mode="json"),
        "pipeline_spec": pipeline_spec.model_dump(mode="json"),
        "proposed_execution_plan": plan.model_dump(mode="json") if plan else None,
        "stage_id": "policy_gate",
        "run_id": run_id,
    }
    payload.update(overrides)
    return PolicyInputFacts(**payload)


@requires_opa
class TestLiveOPAEvaluation:
    def test_governed_python_plan_passes_policy_gate(
        self, live_pdp: PolicyDecisionPoint, python_project_profile, phase_a_pipeline_spec
    ) -> None:
        """End-to-end: governed catalog -> planner plan -> policy_gate == pass."""
        planner = Planner(
            template_registry=TemplateRegistry(),
            policy_spec=live_pdp._policy_spec,
        )
        plan = planner.build_execution_plan(
            python_project_profile,
            phase_a_pipeline_spec,
            live_pdp.policy_version,
            run_id="run-int-1",
        )
        facts = build_gate_facts(plan, python_project_profile, phase_a_pipeline_spec)

        result = live_pdp.evaluate_gate("policy_gate", facts)

        assert result.decision is PolicyDecision.PASS, result.reasons

    def test_critical_findings_fail_security_gate(
        self, live_pdp: PolicyDecisionPoint, python_project_profile, phase_a_pipeline_spec
    ) -> None:
        planner = Planner(
            template_registry=TemplateRegistry(),
            policy_spec=live_pdp._policy_spec,
        )
        plan = planner.build_execution_plan(
            python_project_profile,
            phase_a_pipeline_spec,
            live_pdp.policy_version,
            run_id="run-int-2",
        )
        findings = [
            {
                "severity": "critical",
                "scanner": "trivy",
                "rule_id": "CVE-2026-0001",
                "component": "openssl",
                "disposition": "open",
            }
        ]
        facts = build_gate_facts(
            plan,
            python_project_profile,
            phase_a_pipeline_spec,
            run_id="run-int-2",
            findings=findings,
        )

        result = live_pdp.evaluate_gate("policy_gate", facts)

        assert result.decision is PolicyDecision.FAIL
        assert any("critical" in reason and "exceed" in reason for reason in result.reasons)

    def test_human_approval_fails_closed_without_approver_groups(
        self, live_pdp: PolicyDecisionPoint, python_project_profile
    ) -> None:
        """Governed catalog has empty approver_groups -> high risk tier can never pass."""
        facts = PolicyInputFacts(
            project_profile=python_project_profile.model_dump(mode="json"),
            pipeline_spec={
                "repository": {"repo_id": "example-org/payments-api"},
                "trigger": {"branch": "main"},
            },
            stage_id="human_approval",
            run_id="run-int-3",
        )

        result = live_pdp.evaluate_gate("human_approval", facts)

        assert result.decision is PolicyDecision.FAIL
        assert any("fail closed" in reason for reason in result.reasons)

    def test_human_approval_passes_with_valid_approval(
        self, audit_store_integration: AuditStore, python_project_profile
    ) -> None:
        """With approver groups configured and a matching approval, the gate passes."""
        from ci_agent.core.models.policy_spec import ApprovalPolicy
        from ci_agent.governance import load_policy_spec

        governed = load_policy_spec()
        approval_enabled = governed.model_copy(
            update={
                "approval_policy": ApprovalPolicy(
                    require_human_approval_for=["high", "regulated"],
                    approver_groups=["security-champions"],
                )
            }
        )
        client = OPAClient(base_url=OPA_URL)
        pdp = PolicyDecisionPoint(
            opa_client=client, audit_store=audit_store_integration, policy_spec=approval_enabled
        )
        facts = PolicyInputFacts(
            project_profile=python_project_profile.model_dump(mode="json"),
            pipeline_spec={
                "repository": {"repo_id": "example-org/payments-api"},
                "trigger": {"branch": "main"},
            },
            stage_id="human_approval",
            approvals=[{"approver_group": "security-champions", "status": "approved"}],
            run_id="run-int-3b",
        )

        result = pdp.evaluate_gate("human_approval", facts)

        assert result.decision is PolicyDecision.PASS, result.reasons
        client.close()

    def test_disallowed_repository_fails_identity_policy(
        self, live_pdp: PolicyDecisionPoint, python_project_profile
    ) -> None:
        facts = PolicyInputFacts(
            project_profile=python_project_profile.model_dump(mode="json"),
            pipeline_spec={
                "repository": {"repo_id": "rogue-org/stealer"},
                "trigger": {"branch": "main"},
            },
            stage_id="plan_approval",
            run_id="run-int-4",
        )

        result = live_pdp.evaluate_gate("plan_approval", facts)

        assert result.decision is PolicyDecision.FAIL
        assert any("rogue-org/stealer" in reason for reason in result.reasons)

    def test_unreachable_opa_fails_closed(self, audit_store_integration: AuditStore) -> None:
        from ci_agent.governance import load_policy_spec
        from ci_agent.policy.opa_client import OPAClient as RealClient

        dead_client = RealClient(base_url="http://localhost:59999", timeout_seconds=0.5)
        pdp = PolicyDecisionPoint(
            opa_client=dead_client,
            audit_store=audit_store_integration,
            policy_spec=load_policy_spec(),
        )
        facts = PolicyInputFacts(
            project_profile={"risk_tier": "low"},
            pipeline_spec={
                "repository": {"repo_id": "example-org/payments-api"},
                "trigger": {"branch": "main"},
            },
            stage_id="tool_gate",
            run_id="run-int-5",
        )

        result = pdp.evaluate_gate("tool_gate", facts)

        assert result.decision is PolicyDecision.FAIL
        assert result.reasons[0] == "policy engine unavailable — fail closed"
        # The fail-closed decision is audited too.
        trail = audit_store_integration.get_audit_trail("run-int-5")
        assert trail and trail[0].event_type == "policy_decision"
        dead_client.close()
