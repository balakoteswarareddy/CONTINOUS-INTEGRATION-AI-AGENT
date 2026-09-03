"""Policy Decision Point orchestration (Batch 3, Task A; Report Sections 4.2, 6, 18).

Deterministic, fail-closed policy evaluation: the PDP maps a gate's stage_id to
the relevant Rego policy families, evaluates each against OPA, and aggregates.
ANY failure — a family deciding "fail", OPA being unreachable, an empty OPA
result — produces an overall "fail" decision. An unavailable policy engine is
NEVER an implicit pass (Section 18: "No component can publish an artifact
without satisfying the required deterministic policy gates").

Every evaluation call, regardless of outcome, is persisted as a
``policy_decision`` audit event via the Batch 2 AuditStore.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision
from ci_agent.core.models.policy_spec import PolicySpec
from ci_agent.db.models import PolicyDecisionRecord, utcnow
from ci_agent.governance import load_policy_spec
from ci_agent.policy.models import PolicyDecisionResult, PolicyInputFacts
from ci_agent.policy.opa_client import OPAClient, OPAUnavailableError

REGO_PACKAGE_PREFIX = "ci_agent"

# Gate (stage_id) -> policy families that must approve it (Report Section 5.1
# stage list + Section 4.2 component responsibilities). A stage not listed
# here evaluates ALL families (fail-closed breadth; see NOTES.md).
STAGE_POLICY_FAMILIES: dict[str, tuple[str, ...]] = {
    "policy_gate": ("identity_policy", "tool_policy", "security_policy", "build_policy"),
    "security_gate": ("security_policy",),
    "tool_gate": ("tool_policy",),
    "build_gate": ("build_policy",),
    "artifact_gate": ("artifact_policy",),
    # Batch 7 (Section 5.2 Stage 8: "Push only after required gates pass"):
    # the publish gate checks BOTH the image-scan findings (security) and the
    # artifact supply-chain requirements (SBOM/signature present).
    "publish_gate": ("security_policy", "artifact_policy"),
    "human_approval": ("approval_policy",),
    "merge_decision": ("approval_policy", "ai_policy"),
    "plan_approval": ("identity_policy", "tool_policy", "build_policy", "artifact_policy"),
    "ai_gate": ("ai_policy",),
}

ALL_FAMILIES: tuple[str, ...] = (
    "identity_policy",
    "tool_policy",
    "security_policy",
    "build_policy",
    "artifact_policy",
    "approval_policy",
    "ai_policy",
)

# Map planner stage ids to the scan vocabulary the security Rego checks.
SCAN_STAGE_TO_SCAN_TYPE: dict[str, str] = {
    "secret_scan": "secret_scan",
    "dependency_scan": "sca",
    "sast": "sast",
}

FAIL_CLOSED_REASON = "policy engine unavailable — fail closed"
AUDIT_EVENT_TYPE = "policy_decision"
UNATTRIBUTED_RUN_ID = "policy-decision:unattributed"


class PolicyDecisionPoint:
    """Deterministic gate evaluation against OPA + the governed PolicySpec.

    MVP uses the org-wide governed catalog only; per-project policy overrides
    are a future capability (accepted here as an optional argument for forward
    compatibility, documented in NOTES.md).
    """

    def __init__(
        self,
        opa_client: OPAClient,
        audit_store: AuditStore,
        policy_spec: PolicySpec | None = None,
        session_factory: sessionmaker[Session] | None = None,
        exception_service: Any | None = None,
    ) -> None:
        self._opa_client = opa_client
        self._audit_store = audit_store
        self._policy_spec = policy_spec or load_policy_spec()
        # Optional persistence of every decision as a PolicyDecisionRecord row
        # (Batch 5): evidence assembly reads these instead of scraping logs.
        self._session_factory = session_factory
        # Batch 7 (Task D; Sections 6/18): read-only exception lookup. The PDP
        # may WAIVE a would-be fail when a governed, non-expired exception
        # covers it — it can NEVER CREATE or extend an exception (Section 7.3
        # "Policy bypass"; inspection-tested). The service is the sole write
        # path and lives behind the admin API.
        self._exception_service = exception_service

    @property
    def policy_version(self) -> str:
        return self._policy_spec.policy_version

    def evaluate_gate(self, stage_id: str, facts: PolicyInputFacts) -> PolicyDecisionResult:
        """Evaluate one gate; aggregate; persist an audit event; fail closed."""
        notes: list[str] = []
        families = STAGE_POLICY_FAMILIES.get(stage_id)
        if families is None:
            families = ALL_FAMILIES
            notes.append(f"unknown stage_id {stage_id!r}: evaluated all policy families")

        opa_input = self._build_opa_input(stage_id, facts)

        reasons: list[str] = list(notes)
        overall = PolicyDecision.PASS
        failed_families: list[str] = []
        family_results: dict[str, Any] = {}
        for family in families:
            try:
                result = self._opa_client.evaluate(f"{REGO_PACKAGE_PREFIX}/{family}", opa_input)
            except OPAUnavailableError as exc:
                return self._fail_closed(stage_id, facts, families, exc, notes)

            family_decision = str(result.get("decision", "")).lower()
            family_reasons = [str(r) for r in result.get("reasons", [])]
            family_results[family] = result or {"decision": "missing"}

            if family_decision == "pass":
                continue
            if family_decision == "waived":
                # A waiver never flips an overall fail; it only records context.
                continue
            overall = PolicyDecision.FAIL
            failed_families.append(family)
            if family_decision == "fail":
                if family_reasons:
                    reasons.extend(f"{family}: {reason}" for reason in family_reasons)
                else:
                    reasons.append(f"{family}: failed (no reasons returned)")
            else:
                # Missing/unrecognized decision -> fail closed.
                reasons.append(f"{family}: policy package returned no decision — fail closed")

        exception_ids: list[str] = []
        if overall is PolicyDecision.FAIL:
            waiver = self._try_waive(stage_id, facts, failed_families)
            if waiver is not None:
                exception_ids, waiver_reasons = waiver
                overall = PolicyDecision.WAIVED
                reasons = [*waiver_reasons, *reasons]

        decision_result = PolicyDecisionResult(
            decision=overall,
            reasons=reasons,
            policy_family="aggregated",
            policy_version=self._policy_spec.policy_version,
            exception_ids=exception_ids,
        )
        self._persist(
            stage_id, facts, decision_result, families, family_results, opa_unavailable=False
        )
        return decision_result

    # ------------------------------------------------------- exception waiver

    def _try_waive(
        self, stage_id: str, facts: PolicyInputFacts, failed_families: list[str]
    ) -> tuple[list[str], list[str]] | None:
        """Convert a would-be FAIL into WAIVED when governed exceptions cover it.

        Batch 7 (Task D; Sections 6 and 18): reads ACTIVE exceptions ONLY —
        expiry is derived from the clock inside the service, so an expired or
        revoked exception waives nothing. Conservative matching:

        * EVERY failed family must be covered — a partial waiver still fails
          (a remaining uncovered violation cannot ride along on an unrelated
          exception);
        * for security_policy, the family is covered only when EVERY failing
          finding's rule id is covered (rule-scoped exceptions cover exactly
          their rule; wildcards cover the family);
        * project scope must match the pipeline spec's project_id.

        Returns ``(exception_ids, reasons)`` or ``None`` when uncovered.
        """
        if self._exception_service is None or not failed_families:
            return None
        project_id = str((facts.pipeline_spec or {}).get("project_id", ""))
        if not project_id:
            return None
        exception_ids: list[str] = []
        waiver_reasons: list[str] = []
        for family in failed_families:
            if family == "security_policy":
                failing_rules: list[str] = sorted(
                    {str(f["rule_id"]) for f in facts.findings if f.get("rule_id")}
                )
                covering: dict[str, Any] = {}
                rules_to_check: list[str | None] = list(failing_rules) if failing_rules else [None]
                for rule in rules_to_check:
                    match = self._exception_service.find_covering_exception(
                        project_id, family, rule
                    )
                    if match is None:
                        return None  # an uncovered rule -> no waiver for the family
                    covering[match.id] = match
                exception_ids.extend(sorted(covering))
            else:
                match = self._exception_service.find_covering_exception(project_id, family, None)
                if match is None:
                    return None
                exception_ids.append(match.id)
            waiver_reasons.append(
                f"{family}: waived by exception for project {project_id!r} "
                "(granted outside the model; expires automatically)"
            )
        return exception_ids, waiver_reasons

    # ------------------------------------------------------------------ internals

    def _fail_closed(
        self,
        stage_id: str,
        facts: PolicyInputFacts,
        families: tuple[str, ...],
        error: OPAUnavailableError,
        notes: list[str],
    ) -> PolicyDecisionResult:
        """HARD REQUIREMENT: OPA unavailable == decision "fail" (Section 18)."""
        result = PolicyDecisionResult(
            decision=PolicyDecision.FAIL,
            reasons=[FAIL_CLOSED_REASON, str(error), *notes],
            policy_family="aggregated",
            policy_version=self._policy_spec.policy_version,
        )
        self._persist(
            stage_id,
            facts,
            result,
            families,
            {"opa_error": str(error)},
            opa_unavailable=True,
        )
        return result

    def _build_opa_input(self, stage_id: str, facts: PolicyInputFacts) -> dict[str, Any]:
        """Compose the OPA input document.

        Shape (kept consistent with the .rego files' mapping comments):
          input.project_profile / pipeline_spec / proposed_execution_plan /
          stage_id / findings (verbatim from PolicyInputFacts) + input.policy
          (the governed PolicySpec) + input.runtime (derived runtime facts).
        """
        document = facts.model_dump(mode="json")
        document["policy"] = self._policy_spec.model_dump(mode="json")
        document["runtime"] = self._build_runtime_facts(facts)
        return document

    @staticmethod
    def _build_runtime_facts(facts: PolicyInputFacts) -> dict[str, Any]:
        """Derive runtime facts deterministically from the input facts.

        Derivation rules (documented in NOTES.md):
        - repository/branch come from the pipeline spec's repository/trigger.
        - tools/images come from the proposed plan's resolved steps.
        - scans_executed maps planner scan stages onto the security Rego's
          scan vocabulary (secret_scan / sca / sast).
        - egress domains are empty until runner adapters enforce networking.
        - approvals/ai_invocation pass through from the input facts when the
          orchestrator provides them (approval/AI workflow batches).
        """
        pipeline = facts.pipeline_spec or {}
        repository = pipeline.get("repository") or {}
        trigger = pipeline.get("trigger") or {}
        plan = facts.proposed_execution_plan or {}
        steps = plan.get("resolved_steps") or []

        tools = [
            {
                "name": step.get("tool_name"),
                "version": step.get("tool_version"),
                "container_image": step.get("container_image"),
            }
            for step in steps
        ]
        images = sorted({step["container_image"] for step in steps if step.get("container_image")})
        scans_executed = sorted(
            {
                SCAN_STAGE_TO_SCAN_TYPE[step["stage_id"]]
                for step in steps
                if step.get("stage_id") in SCAN_STAGE_TO_SCAN_TYPE
            }
        )
        timeouts = [step["timeout_seconds"] for step in steps if "timeout_seconds" in step]

        return {
            "repository": repository.get("repo_id") or repository.get("url"),
            "branch": trigger.get("branch"),
            "identity": None,  # identity binding arrives with runner adapters
            "tools": tools,
            "base_images": images,
            "egress_domains": [],
            "step_timeout_seconds": max(timeouts) if timeouts else 0,
            "scans_executed": scans_executed,
            "risk_tier": (facts.project_profile or {}).get("risk_tier"),
            "approvals": facts.approvals,
            "ai_invocation": facts.ai_invocation,
            # Batch 7: supply-chain artifact facts for artifact_policy.rego.
            "artifacts": facts.artifacts,
        }

    def _persist(
        self,
        stage_id: str,
        facts: PolicyInputFacts,
        result: PolicyDecisionResult,
        families: tuple[str, ...],
        family_results: dict[str, Any],
        *,
        opa_unavailable: bool,
    ) -> None:
        """Record the evaluation as an audit event — ALWAYS, pass or fail."""
        self._audit_store.append_event(
            facts.run_id or UNATTRIBUTED_RUN_ID,
            AUDIT_EVENT_TYPE,
            {
                "stage_id": stage_id,
                "decision": result.decision.value,
                "reasons": result.reasons,
                "policy_family": result.policy_family,
                "policy_version": result.policy_version,
                "families_evaluated": list(families),
                "family_results": family_results,
                "exception_ids": list(result.exception_ids),
                "opa_unavailable": opa_unavailable,
                "evaluation_id": str(uuid.uuid4()),
            },
        )
        if self._session_factory is not None:
            with self._session_factory() as session:
                session.add(
                    PolicyDecisionRecord(
                        run_id=facts.run_id or UNATTRIBUTED_RUN_ID,
                        stage_id=stage_id,
                        decision=result.decision.value,
                        policy_family=result.policy_family,
                        policy_version=result.policy_version,
                        reasons_json=json.dumps(result.reasons),
                        exception_ids_json=json.dumps(result.exception_ids),
                        evaluated_at=utcnow(),
                    )
                )
                session.commit()
