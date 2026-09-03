"""Unit tests for PolicyDecisionPoint aggregation + fail-closed behavior (Batch 3, Task A)."""

from __future__ import annotations

from typing import Any

import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision
from ci_agent.policy.models import PolicyInputFacts
from ci_agent.policy.opa_client import OPAUnavailableError
from ci_agent.policy.policy_decision_point import (
    ALL_FAMILIES,
    STAGE_POLICY_FAMILIES,
    PolicyDecisionPoint,
)


class FakeOPAClient:
    """Scripted stand-in for OPAClient (unit tests only — never in prod paths)."""

    def __init__(
        self,
        results: dict[str, dict[str, Any]] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.results = results or {}
        self.error = error
        self.calls: list[str] = []
        self.inputs: list[dict[str, Any]] = []

    def evaluate(self, package: str, input_facts: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(package)
        self.inputs.append(input_facts)
        if self.error is not None:
            raise self.error
        return self.results.get(package, {"decision": "pass", "reasons": []})


@pytest.fixture()
def pdp(audit_store: AuditStore, approved_policy_spec) -> PolicyDecisionPoint:
    return PolicyDecisionPoint(
        opa_client=FakeOPAClient(),  # type: ignore[arg-type]
        audit_store=audit_store,
        policy_spec=approved_policy_spec,
    )


def make_facts(run_id: str | None = "run-1", **overrides: Any) -> PolicyInputFacts:
    payload: dict[str, Any] = {
        "project_profile": {"risk_tier": "high"},
        "pipeline_spec": {
            "repository": {"repo_id": "example-org/payments-api", "url": "https://github.com/x/y"},
            "trigger": {"branch": "main"},
        },
        "stage_id": "policy_gate",
        "run_id": run_id,
    }
    payload.update(overrides)
    return PolicyInputFacts(**payload)


class TestAggregation:
    def test_all_families_pass_overall_pass(
        self, pdp: PolicyDecisionPoint, audit_store: AuditStore
    ) -> None:
        result = pdp.evaluate_gate("policy_gate", make_facts())

        assert result.decision is PolicyDecision.PASS
        assert result.reasons == []
        assert result.policy_version == "1.0.0"
        assert result.policy_family == "aggregated"
        # Audit entry ALWAYS written (pass included).
        trail = audit_store.get_audit_trail("run-1")
        assert [entry.event_type for entry in trail] == ["policy_decision"]

    def test_any_family_fail_overall_fail_with_concatenated_reasons(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        fake = FakeOPAClient(
            results={
                "ci_agent/identity_policy": {"decision": "pass", "reasons": []},
                "ci_agent/tool_policy": {"decision": "pass", "reasons": []},
                "ci_agent/security_policy": {
                    "decision": "fail",
                    "reasons": ['severity "critical": 1 findings exceed threshold 0'],
                },
                "ci_agent/build_policy": {"decision": "pass", "reasons": []},
            }
        )
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]

        result = pdp.evaluate_gate("security_gate", make_facts(stage_id="security_gate"))

        assert result.decision is PolicyDecision.FAIL
        assert result.reasons == [
            'security_policy: severity "critical": 1 findings exceed threshold 0'
        ]

    def test_multiple_failures_concatenated(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        fake = FakeOPAClient(
            results={
                "ci_agent/identity_policy": {"decision": "fail", "reasons": ["repo not allowed"]},
                "ci_agent/tool_policy": {"decision": "fail", "reasons": ["tool x not approved"]},
                "ci_agent/security_policy": {"decision": "fail", "reasons": ["findings exceed"]},
                "ci_agent/build_policy": {"decision": "fail", "reasons": ["image not allowed"]},
            }
        )
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]

        result = pdp.evaluate_gate("policy_gate", make_facts())

        assert result.decision is PolicyDecision.FAIL
        assert len(result.reasons) == 4
        assert result.reasons[0] == "identity_policy: repo not allowed"

    def test_stage_mapping_selects_families(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        fake = FakeOPAClient()
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]

        pdp.evaluate_gate("human_approval", make_facts(stage_id="human_approval"))

        assert fake.calls == ["ci_agent/approval_policy"]

    def test_unknown_stage_evaluates_all_families_fail_closed_breadth(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        fake = FakeOPAClient()
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]

        result = pdp.evaluate_gate("mystery_gate", make_facts(stage_id="mystery_gate"))

        assert set(fake.calls) == {f"ci_agent/{family}" for family in ALL_FAMILIES}
        assert "unknown stage_id" in result.reasons[0]

    def test_stage_mapping_table_contains_spec_mandated_gates(self) -> None:
        # Section 5.1 / Task A examples: policy_gate (security+tool+build),
        # human_approval (approval).
        assert set(STAGE_POLICY_FAMILIES["policy_gate"]) >= {
            "security_policy",
            "tool_policy",
            "build_policy",
        }
        assert STAGE_POLICY_FAMILIES["human_approval"] == ("approval_policy",)


class TestFailClosed:
    def test_opa_unavailable_is_fail_with_dedicated_reason(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        """HARD REQUIREMENT: unavailable policy engine must never pass."""
        fake = FakeOPAClient(error=OPAUnavailableError("connection refused"))
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]

        result = pdp.evaluate_gate("policy_gate", make_facts())

        assert result.decision is PolicyDecision.FAIL
        assert result.reasons[0] == "policy engine unavailable — fail closed"
        assert "connection refused" in result.reasons[1]

    def test_opa_unavailable_still_writes_audit_entry(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        fake = FakeOPAClient(error=OPAUnavailableError("connection refused"))
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]

        pdp.evaluate_gate("policy_gate", make_facts())

        trail = audit_store.get_audit_trail("run-1")
        assert len(trail) == 1
        import json

        payload = json.loads(trail[0].payload_json)
        assert payload["decision"] == "fail"
        assert payload["opa_unavailable"] is True

    def test_missing_decision_from_opa_fails_closed(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        fake = FakeOPAClient(results={"ci_agent/security_policy": {}})
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]

        result = pdp.evaluate_gate("security_gate", make_facts(stage_id="security_gate"))

        assert result.decision is PolicyDecision.FAIL
        assert "no decision — fail closed" in result.reasons[0]

    def test_evaluate_method_of_real_client_speaks_audit(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        """The audit event type must stay 'policy_decision' (spec'd)."""
        pdp = PolicyDecisionPoint(FakeOPAClient(), audit_store, approved_policy_spec)  # type: ignore[arg-type]
        pdp.evaluate_gate("tool_gate", make_facts(stage_id="tool_gate"))

        assert audit_store.get_audit_trail("run-1")[0].event_type == "policy_decision"


class TestAuditWiring:
    def test_unattributed_evaluations_use_synthetic_run_id(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        pdp = PolicyDecisionPoint(FakeOPAClient(), audit_store, approved_policy_spec)  # type: ignore[arg-type]

        pdp.evaluate_gate("tool_gate", make_facts(run_id=None, stage_id="tool_gate"))

        assert audit_store.get_audit_trail("policy-decision:unattributed")

    def test_audit_payload_contains_decision_and_families(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        import json

        pdp = PolicyDecisionPoint(FakeOPAClient(), audit_store, approved_policy_spec)  # type: ignore[arg-type]
        pdp.evaluate_gate("policy_gate", make_facts())

        entry = audit_store.get_audit_trail("run-1")[0]
        payload = json.loads(entry.payload_json)
        assert payload["stage_id"] == "policy_gate"
        assert payload["decision"] == "pass"
        assert set(payload["families_evaluated"]) == set(STAGE_POLICY_FAMILIES["policy_gate"])
        assert payload["policy_version"] == "1.0.0"


class TestInputBuilding:
    def test_opa_input_contains_policy_and_runtime(
        self, audit_store: AuditStore, approved_policy_spec
    ) -> None:
        fake = FakeOPAClient()
        pdp = PolicyDecisionPoint(fake, audit_store, approved_policy_spec)  # type: ignore[arg-type]
        facts = make_facts(
            proposed_execution_plan={
                "resolved_steps": [
                    {
                        "step_id": "s1",
                        "stage_id": "secret_scan",
                        "tool_name": "gitleaks",
                        "tool_version": "8.18.2",
                        "container_image": "python:3.11-slim",
                        "command_template_id": "scan.gitleaks",
                        "timeout_seconds": 300,
                    }
                ]
            }
        )

        pdp.evaluate_gate("policy_gate", facts)

        sent = fake.inputs[0]
        # input.policy mirrors the governed PolicySpec (Rego mapping contract).
        assert sent["policy"]["policy_version"] == "1.0.0"
        assert sent["policy"]["tool_policy"]["approved_tool_versions"]["gitleaks"] == "8.18.2"
        # input.runtime is derived deterministically from the facts.
        assert sent["runtime"]["repository"] == "example-org/payments-api"
        assert sent["runtime"]["branch"] == "main"
        assert sent["runtime"]["tools"] == [
            {
                "name": "gitleaks",
                "version": "8.18.2",
                "container_image": "python:3.11-slim",
            }
        ]
        assert sent["runtime"]["base_images"] == ["python:3.11-slim"]
        assert sent["runtime"]["scans_executed"] == ["secret_scan"]
        assert sent["runtime"]["step_timeout_seconds"] == 300
        assert sent["runtime"]["risk_tier"] == "high"
        assert sent["stage_id"] == "policy_gate"
