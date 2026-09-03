"""Phase A orchestrator (Batch 5; Report Sections 4.2, 5.1, 10).

Drives one accepted run through the explicit :class:`RunState` machine:

* entry point 1 — the ingress webhook calls ``advance(run_id, {"type":
  "run_created"})`` after run creation;
* entry point 2 — the Execution Observer's stage transitions feed
  ``advance(run_id, {"type": "stage_transition", ...})``;
* entry point 3 — the approval API feeds ``advance(run_id, {"type":
  "approval", ...})``.

The flow: plan (deterministic Planner) -> ``plan_approval`` PDP gate ->
dispatch via the RunnerAdapter -> observer stage transitions advance the run
state -> after all tool stages are terminal, a ``policy_gate`` evaluation on
exit-code-derived findings (MVP: Batch 6 enriches with scanner output) ->
either AWAITING_APPROVAL (risk tier) or APPROVED -> merge decision published
as a Check Run linking the compliance evidence report.

Invariants: EVERY state change is dual-written (RunRecord.current_state AND an
audit event); policy decisions are never retried (Section 10) and always come
from the PDP; any unexpected control-plane error parks the run in ERROR
(fail closed), never in a fake "green".
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.adapters.base import RunnerAdapter
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision, RiskTier
from ci_agent.core.models.execution_plan import ExecutionPlan
from ci_agent.core.models.pipeline_spec import PipelineSpec
from ci_agent.db.models import ApprovalRecord, RunRecord, StageExecutionRecord, utcnow
from ci_agent.orchestrator.run_state import (
    TERMINAL_RUN_STATES,
    RunState,
    assert_run_transition,
)
from ci_agent.policy.models import PolicyInputFacts
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard

# Check Run name carrying the published merge decision (Section 5.1 stage 10).
MERGE_DECISION_CHECK_NAME = "ci-agent merge decision"

# Tool stage id -> the run state its SUCCESS produces.
STAGE_TO_RUN_STATE: dict[str, RunState] = {
    "checkout": RunState.CHECKED_OUT,
    "format_lint": RunState.BASELINE_VALIDATED,
    "sast": RunState.SAST_DONE,
    "unit_tests": RunState.TESTS_DONE,
    "secret_scan": RunState.SECURITY_CHECKED,
    "dependency_scan": RunState.SECURITY_CHECKED,
}

# Chained states: the format_lint stage validates the baseline AND records the
# lint gate — both transitions are dual-written (explicit, Section 10).
AUTO_ADVANCE: dict[RunState, RunState] = {
    RunState.BASELINE_VALIDATED: RunState.LINTED,
}

# Stages whose success is required before the policy gate may be evaluated.
PRE_POLICY_STAGES: frozenset[str] = frozenset(STAGE_TO_RUN_STATE)


class OrchestrationError(Exception):
    """Internal orchestration failure (audited; run parked in ERROR)."""


class CallerError(ValueError):
    """Malformed/not-actionable caller request (HTTP 409 shape).

    NOT an orchestration failure: the run's state is untouched — no parking
    in ERROR, just a rejected request.
    """


def _canonical_spec_hash(spec_document: dict[str, Any]) -> str:
    """sha256 over the canonical (sorted-keys) spec JSON — the spec hash ref."""
    canonical = json.dumps(spec_document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PhaseAOrchestrator:
    """Drive Phase A pipeline runs through the explicit state machine."""

    def __init__(
        self,
        *,
        audit_store: AuditStore,
        session_factory: sessionmaker[Session],
        project_registry: ProjectRegistry,
        planner: Any,
        pdp: PolicyDecisionPoint,
        adapter: RunnerAdapter,
        github_client: Any,
        concurrency_guard: ConcurrencyGuard,
        policy_spec_version: str,
    ) -> None:
        self._audit_store = audit_store
        self._session_factory = session_factory
        self._registry = project_registry
        self._planner = planner
        self._pdp = pdp
        self._adapter = adapter
        self._github = github_client
        self._guard = concurrency_guard
        self._policy_version = policy_spec_version

    # ------------------------------------------------------------------ public

    def advance(self, run_id: str, trigger_event: dict[str, Any]) -> dict[str, Any] | None:
        """Advance one run according to a control-plane trigger event."""
        event_type = str(trigger_event.get("type", ""))
        handlers = {
            "run_created": self._on_run_created,
            "stage_transition": self._on_stage_transition,
            "approval": self._on_approval,
        }
        handler = handlers.get(event_type)
        if handler is None:
            raise CallerError(f"unknown trigger event type {event_type!r}")
        try:
            return handler(run_id, trigger_event)
        except OrchestrationError:
            raise
        except CallerError:
            raise  # caller mistakes never mutate run state
        except Exception as exc:
            self._park_in_error(run_id, f"{type(exc).__name__}: {exc}")
            raise OrchestrationError(str(exc)) from exc

    def on_stage_transition(
        self, run_id: str, stage_id: str, status: str, exit_code: int | None = None
    ) -> dict[str, Any] | None:
        """Observer callback: translate a stage outcome into a trigger event."""
        if stage_id.startswith("internal.") or stage_id == "workflow":
            return None  # control-plane orchestrated; GitHub echo events ignored
        return self.advance(
            run_id,
            {
                "type": "stage_transition",
                "stage_id": stage_id,
                "status": status,
                "exit_code": exit_code,
            },
        )

    # ------------------------------------------------------- run_created entry

    def _on_run_created(self, run_id: str, _event: dict[str, Any]) -> dict[str, Any]:
        run = self._require_run(run_id)
        self._transition(run_id, None, RunState.TRIGGER_VALIDATED)

        profile = self._registry.get_profile(run.project_id)
        spec_document = self._registry.get_pipeline_spec(run.project_id)
        spec = PipelineSpec.model_validate(spec_document)
        spec_ref = _canonical_spec_hash(spec_document)
        plan = self._planner.build_execution_plan(
            profile, spec, self._policy_version, run_id=run_id
        )
        with self._session_factory() as session:
            persisted = session.get(RunRecord, run_id)
            assert persisted is not None, f"run {run_id!r} vanished mid-planning"
            persisted.pipeline_spec_ref = spec_ref
            session.commit()

        # Gate 1: plan approval (fail -> FAILED + blocked merge decision).
        facts = self._plan_facts(run, profile, spec_document, plan)
        decision = self._pdp.evaluate_gate("plan_approval", facts)
        if decision.decision is not PolicyDecision.PASS:
            reason = "plan_approval rejected: " + "; ".join(decision.reasons)
            self._transition(run_id, RunState.TRIGGER_VALIDATED, RunState.FAILED, reason=reason)
            self._publish_merge_decision(run, approved=False, reasons=decision.reasons)
            return {"state": RunState.FAILED.value, "reason": "plan_approval rejected"}

        # Backpressure: per-project in-flight quota BEFORE dispatch (Section 10).
        if not self._guard.acquire(run.project_id):
            reason = (
                f"concurrency limit reached for project {run.project_id!r} " "(max in-flight runs)"
            )
            self._transition(run_id, RunState.TRIGGER_VALIDATED, RunState.ERROR, reason=reason)
            return {"state": RunState.ERROR.value, "reason": "concurrency limit"}

        try:
            artifact = self._adapter.compile(
                plan,
                metadata={
                    "repository": run.repository,
                    "source_sha": run.source_sha or "",
                },
            )
            dispatch_ref = self._adapter.dispatch(artifact, run_id)
        except Exception:
            self._release_guard(run.project_id)  # no quota leak on failed dispatch
            raise
        with self._session_factory() as session:
            persisted = session.get(RunRecord, run_id)
            assert persisted is not None, f"run {run_id!r} vanished mid-dispatch"
            persisted.dispatch_branch = dispatch_ref.branch
            persisted.external_run_id = dispatch_ref.external_run_id
            session.commit()
        self._audit(run_id, "run_dispatched", {"dispatch_branch": dispatch_ref.branch})
        return {"state": RunState.TRIGGER_VALIDATED.value, "dispatched": True}

    # ------------------------------------------------- stage_transition entry

    def _on_stage_transition(self, run_id: str, event: dict[str, Any]) -> dict[str, Any] | None:
        run = self._require_run(run_id)
        current = self._current_state(run_id)
        stage_id = str(event.get("stage_id", ""))
        status = str(event.get("status", ""))

        if current is None:
            # This run never advanced past creation (e.g. an observer event for
            # a run dispatched by an older control plane). Skip, audited.
            self._audit(
                run_id,
                "run_state_noop",
                {"reason": "no current state", "stage_id": stage_id},
            )
            return None

        if status != "passed":
            reason = f"stage {stage_id!r} finished with status {status!r}"
            self._transition(run_id, current, RunState.FAILED, reason=reason)
            self._publish_merge_decision(run, approved=False, reasons=[reason])
            self._release_guard(run.project_id)
            return {"state": RunState.FAILED.value, "reason": reason}

        target = STAGE_TO_RUN_STATE.get(stage_id)
        if target is None:
            self._audit(
                run_id,
                "run_state_noop",
                {"reason": f"stage {stage_id!r} is not state-mapped"},
            )
            return None
        if current in TERMINAL_RUN_STATES:
            # Late/duplicate events after a terminal state: graceful no-op
            # (Section 10 — out-of-order and duplicate events never corrupt).
            self._audit(
                run_id,
                "run_state_noop",
                {"reason": f"run already terminal ({current.value})", "stage_id": stage_id},
            )
            return {"state": current.value, "note": "run already terminal"}

        if target is RunState.SECURITY_CHECKED:
            # Both scans converge on SECURITY_CHECKED; the second arrival is
            # legal even from within SECURITY_CHECKED itself.
            if current is not RunState.SECURITY_CHECKED:
                assert_run_transition(current, target)  # may raise -> ERROR
                self._transition(run_id, current, target, reason=f"stage {stage_id!r} passed")
            pending = self._pending_pre_policy_stages(run_id)
            if pending:
                # Gate only fires once EVERY pre-policy stage is passed —
                # scans may complete out of order.
                self._audit(
                    run_id,
                    "run_state_noop",
                    {"reason": "waiting for remaining pre-policy stages", "pending": pending},
                )
                return {"state": RunState.SECURITY_CHECKED.value, "pending_stages": pending}
            return self._evaluate_policy_gate(run_id)

        if current == target:
            self._audit(run_id, "run_state_noop", {"reason": "already in target state"})
            return None

        assert_run_transition(current, target)  # may raise -> parked ERROR
        self._transition(run_id, current, target, reason=f"stage {stage_id!r} passed")
        while target in AUTO_ADVANCE:
            chained = AUTO_ADVANCE[target]
            self._transition(run_id, target, chained, reason="chained state advance")
            target = chained
        return {"state": target.value}

    # -------------------------------------------------------- policy gate step

    def _pending_pre_policy_stages(self, run_id: str) -> list[str]:
        """Pre-policy stages not yet recorded as passed (empty = all done)."""
        with self._session_factory() as session:
            records = (
                session.execute(
                    select(StageExecutionRecord).where(
                        StageExecutionRecord.run_id == run_id,
                        StageExecutionRecord.stage_id.in_(sorted(PRE_POLICY_STAGES)),
                    )
                )
                .scalars()
                .all()
            )
        passed = {r.stage_id for r in records if r.status == "passed"}
        return sorted(PRE_POLICY_STAGES - passed)

    def _evaluate_policy_gate(self, run_id: str) -> dict[str, Any]:
        run = self._require_run(run_id)
        self._transition(run_id, RunState.SECURITY_CHECKED, RunState.POLICY_GATE_EVAL)

        profile = self._registry.get_profile(run.project_id)
        spec_document = self._registry.get_pipeline_spec(run.project_id)
        spec = PipelineSpec.model_validate(spec_document)
        plan = self._planner.build_execution_plan(
            profile, spec, self._policy_version, run_id=run_id
        )

        facts = self._gate_facts(run, profile, spec_document, plan)
        decision = self._pdp.evaluate_gate("policy_gate", facts)
        if decision.decision is not PolicyDecision.PASS:
            reason = "policy_gate rejected: " + "; ".join(decision.reasons)
            self._transition(run_id, RunState.POLICY_GATE_EVAL, RunState.FAILED, reason=reason)
            self._publish_merge_decision(run, approved=False, reasons=decision.reasons)
            self._release_guard(run.project_id)
            return {"state": RunState.FAILED.value, "reason": "policy_gate rejected"}

        if self._approval_required(profile):
            reason = f"risk tier {profile.risk_tier.value} requires human approval"
            self._transition(
                run_id,
                RunState.POLICY_GATE_EVAL,
                RunState.AWAITING_APPROVAL,
                reason=reason,
            )
            return {"state": RunState.AWAITING_APPROVAL.value}

        self._transition(run_id, RunState.POLICY_GATE_EVAL, RunState.APPROVED)
        return self._finish(run_id, approved=True, approver="policy:auto-approve")

    def _approval_required(self, profile: Any) -> bool:
        """Deterministic MVP rule: high risk tier requires a human approval."""
        return profile.risk_tier is RiskTier.HIGH

    # ----------------------------------------------------------- approval path

    def _on_approval(self, run_id: str, event: dict[str, Any]) -> dict[str, Any]:
        self._require_run(run_id)  # 404s early for unknown runs
        current = self._current_state(run_id)
        decision = str(event.get("decision", ""))
        approver = str(event.get("approver", "unknown"))
        comment = event.get("comment")

        if current is not RunState.AWAITING_APPROVAL:
            current_name = current.value if current else None
            raise CallerError(f"run {run_id!r} is in state {current_name!r}, not awaiting_approval")
        if decision not in ("approved", "rejected"):
            raise CallerError(f"invalid approval decision {decision!r}")

        target = RunState.APPROVED if decision == "approved" else RunState.REJECTED
        with self._session_factory() as session:
            session.add(
                ApprovalRecord(
                    run_id=run_id,
                    decision=decision,
                    approver=approver,
                    comment=str(comment) if comment is not None else None,
                )
            )
            session.commit()
        self._transition(
            run_id,
            current,
            target,
            reason=f"human approval: {decision} by {approver}",
        )
        self._audit(run_id, "approval_recorded", {"decision": decision, "approver": approver})

        if target is RunState.APPROVED:
            return self._finish(run_id, approved=True, approver=approver)
        return self._finish(run_id, approved=False, reasons=[f"rejected by {approver}"])

    def _finish(
        self,
        run_id: str,
        *,
        approved: bool,
        approver: str | None = None,
        reasons: list[str] | None = None,
    ) -> dict[str, Any]:
        run = self._require_run(run_id)
        self._publish_merge_decision(run, approved=approved, approver=approver, reasons=reasons)
        source = RunState.APPROVED if approved else RunState.REJECTED
        self._transition(run_id, source, RunState.MERGE_DECISION_PUBLISHED)
        self._release_guard(run.project_id)
        return {"state": RunState.MERGE_DECISION_PUBLISHED.value, "approved": approved}

    # --------------------------------------------------------- merge decision

    def _publish_merge_decision(
        self,
        run: RunRecord,
        *,
        approved: bool,
        approver: str | None = None,
        reasons: list[str] | None = None,
    ) -> None:
        """Publish the merge decision as a Check Run (Section 5.1 stage 10).

        The summary links the compliance evidence report; the check run is the
        ONLY machine-visible merge decision (never inferred from logs).
        """
        sha = run.source_sha
        if not sha:
            return  # nothing to attach the decision to (rejected pre-dispatch)
        summary_lines = [
            f"ci-agent merge decision: {'APPROVED' if approved else 'BLOCKED'}",
            (f"Run: /runs/{run.run_id} " f"(report: /runs/{run.run_id}/report?view=compliance)"),
        ]
        if approver:
            summary_lines.append(f"Approved by: {approver}")
        if reasons:
            summary_lines.append("Reasons: " + "; ".join(reasons))
        conclusion = "success" if approved else "failure"
        self._github.post_check_run(
            run.repository,
            sha,
            name=MERGE_DECISION_CHECK_NAME,
            status="completed",
            conclusion=conclusion,
            output={"title": summary_lines[0], "summary": "\n".join(summary_lines)},
        )
        self._audit(
            run.run_id,
            "merge_decision_published",
            {
                "approved": approved,
                "conclusion": conclusion,
                "check_name": MERGE_DECISION_CHECK_NAME,
            },
        )

    # ---------------------------------------------------------------- helpers

    def _plan_facts(
        self,
        run: RunRecord,
        profile: Any,
        spec_document: dict[str, Any],
        plan: ExecutionPlan,
    ) -> PolicyInputFacts:
        return PolicyInputFacts(
            project_profile=profile.model_dump(mode="json"),
            pipeline_spec=spec_document,
            proposed_execution_plan=json.loads(plan.model_dump_json()),
            stage_id="plan_approval",
            run_id=run.run_id,
        )

    def _gate_facts(
        self,
        run: RunRecord,
        profile: Any,
        spec_document: dict[str, Any],
        plan: ExecutionPlan,
    ) -> PolicyInputFacts:
        """Policy gate facts: exit-code-only findings (MVP simplification).

        Failed tool stages become HIGH-severity findings; detailed scanner
        output parsing arrives with Batch 6 (Task C) — never earlier.
        """
        findings: list[dict[str, Any]] = []
        with self._session_factory() as session:
            records = (
                session.execute(
                    select(StageExecutionRecord).where(StageExecutionRecord.run_id == run.run_id)
                )
                .scalars()
                .all()
            )
        for record in records:
            if record.status == "failed" and record.stage_id in PRE_POLICY_STAGES:
                findings.append(
                    {
                        "severity": "high",
                        "scanner": record.stage_id,
                        "rule_id": "stage_exit_code_nonzero",
                        "component": record.stage_id,
                        "disposition": "open",
                    }
                )
        return PolicyInputFacts(
            project_profile=profile.model_dump(mode="json"),
            pipeline_spec=spec_document,
            proposed_execution_plan=json.loads(plan.model_dump_json()),
            stage_id="policy_gate",
            findings=findings,
            run_id=run.run_id,
        )

    def _require_run(self, run_id: str) -> RunRecord:
        with self._session_factory() as session:
            run = session.get(RunRecord, run_id)
            if run is None:
                raise LookupError(f"run {run_id!r} does not exist")
            session.expunge(run)
            return run

    def _current_state(self, run_id: str) -> RunState | None:
        raw = self._require_run(run_id).current_state
        return RunState(raw) if raw else None

    def _transition(
        self,
        run_id: str,
        current: RunState | None,
        target: RunState,
        *,
        reason: str | None = None,
    ) -> None:
        """Dual-write one transition: DB column + audit event (Section 10)."""
        assert_run_transition(current, target)
        self._write_state(run_id, current, target)
        payload: dict[str, Any] = {
            "from": current.value if current else None,
            "to": target.value,
        }
        if reason:
            payload["reason"] = reason
        self._audit(run_id, "run_state_transition", payload)

    def _write_state(self, run_id: str, current: RunState | None, target: RunState) -> None:
        with self._session_factory() as session:
            run = session.get(RunRecord, run_id)
            assert run is not None, f"run {run_id!r} vanished mid-transition"
            persisted_raw = run.current_state
            if persisted_raw != (current.value if current else None):
                # A concurrent writer moved the run: re-validate monotonicity
                # against the persisted position before overwriting it.
                assert_run_transition(RunState(persisted_raw) if persisted_raw else None, target)
            run.current_state = target.value
            run.updated_at = utcnow()
            session.commit()

    def _park_in_error(self, run_id: str, detail: str) -> None:
        """Fail closed: unexpected control-plane errors park the run in ERROR."""
        try:
            current = self._current_state(run_id)
            if current in TERMINAL_RUN_STATES:
                self._audit(
                    run_id,
                    "orchestration_error",
                    {"detail": detail, "note": "run already terminal"},
                )
                return
            if current is not None:
                assert_run_transition(current, RunState.ERROR)
            self._transition(run_id, current, RunState.ERROR, reason=detail)
            self._audit(run_id, "orchestration_error", {"detail": detail})
        except Exception:
            self._audit(
                run_id,
                "orchestration_error",
                {"detail": detail, "note": "park-in-error also failed"},
            )

    def _release_guard(self, project_id: str) -> None:
        try:
            self._guard.release(project_id)
        except Exception:
            self._audit(
                "system",
                "orchestration_error",
                {"detail": f"concurrency guard release failed for {project_id!r}"},
            )

    def _audit(self, run_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self._audit_store.append_event(run_id, event_type, payload)


__all__ = [
    "MERGE_DECISION_CHECK_NAME",
    "STAGE_TO_RUN_STATE",
    "OrchestrationError",
    "PhaseAOrchestrator",
]
