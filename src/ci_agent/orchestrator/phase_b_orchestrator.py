"""Phase B orchestrator (Batch 7, Task E; Report Sections 4.2, 5.2, 8, 10).

Mirrors :class:`~ci_agent.orchestrator.phase_a_orchestrator.PhaseAOrchestrator`
exactly — same dual-write discipline (RunRecord.current_state + audit event),
same fail-closed parking, same one-job-per-stage dispatch seam — for the
Section 5.2 nine-stage supply-chain flow:

    full_build -> integration_tests -> coverage_gate -> container_build ->
    sbom_generate -> image_scan -> sign_attest -> [publish gate] -> publish ->
    record_evidence (terminal EVIDENCE_RECORDED)

Trigger discipline (Section 5.2 — tested explicitly): Phase B starts ONLY
from an APPROVED Phase A merge decision. :meth:`start` re-verifies the run's
state AND the ``merge_decision_published`` audit event's ``approved`` flag —
a failed/rejected Phase A can never reach the supply-chain flow.

Gate-before-push (Section 5.2 Stage 8): the runner jobs are dispatched in
TWO waves. Wave 1 (build … sign_attest) produces the artifact + evidence;
the control plane then evaluates the ``publish_gate`` on REAL facts (image
findings + SBOM/signature presence + REAL signature verification). Only a
PASS (or governed waiver) dispatches Wave 2 (publish + record_evidence) —
the publish job physically does not exist until the gate passes.

Coverage gate: reads ``coverage_percent`` from the stage's structured result
(ci-agent-results.json convention, Batch 4 extended) and compares it with
``PipelineSpec.thresholds["coverage_percent"]`` — fail-closed when coverage
data is missing but a threshold is configured.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.adapters.base import RunnerAdapter
from ci_agent.adapters.router import AdapterRouter, select_runner_name
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import PolicyDecision, Severity, StageStatus
from ci_agent.core.models.execution_plan import ExecutionPlan
from ci_agent.core.models.pipeline_spec import PipelineSpec
from ci_agent.db.models import RunRecord, StageExecutionRecord, utcnow
from ci_agent.exceptions.exception_service import ExceptionService
from ci_agent.orchestrator.phase_a_orchestrator import (
    CallerError,
    OrchestrationError,
    _canonical_spec_hash,
)
from ci_agent.orchestrator.run_state import (
    PHASE_B_SUCCESS_STATE,
    RunState,
    assert_run_transition,
)
from ci_agent.policy.models import PolicyInputFacts
from ci_agent.policy.policy_decision_point import PolicyDecisionPoint
from ci_agent.projects.project_registry import ProjectRegistry
from ci_agent.reliability.concurrency_guard import ConcurrencyGuard
from ci_agent.security.security_evidence_service import SecurityEvidenceService
from ci_agent.supplychain.sbom_service import SBOMService, TagOnlyDigestError
from ci_agent.supplychain.signing_service import SigningService
from ci_agent.telemetry.emitter import TelemetryEmitter
from ci_agent.telemetry.pipeline_event import PipelineRunEvent

# Section 5.2 Stage -> run state (success path).
PHASE_B_STAGE_TO_RUN_STATE: dict[str, RunState] = {
    "full_build": RunState.BUILT,
    "integration_tests": RunState.INTEGRATION_TESTED,
    "coverage_gate": RunState.COVERAGE_CHECKED,
    "container_build": RunState.CONTAINER_BUILT,
    "sbom_generate": RunState.SBOM_GENERATED,
    "image_scan": RunState.IMAGE_SCANNED,
    "sign_attest": RunState.SIGNED,
    "publish": RunState.PUBLISHED,
    "record_evidence": RunState.EVIDENCE_RECORDED,
}

# Dispatch wave 1: artifact production + evidence collection (Section 8).
PHASE_B_WAVE_1_STAGES: tuple[str, ...] = (
    "full_build",
    "integration_tests",
    "coverage_gate",
    "container_build",
    "sbom_generate",
    "image_scan",
    "sign_attest",
)
# Dispatch wave 2: exists ONLY after the publish gate passes (Stage 8:
# "Push only after required gates pass").
PHASE_B_WAVE_2_STAGES: tuple[str, ...] = ("publish", "record_evidence")

PHASE_B_STAGES: frozenset[str] = frozenset(PHASE_B_STAGE_TO_RUN_STATE)

# States in which the Phase B state machine actively advances.
PHASE_B_ACTIVE_STATES: frozenset[RunState] = frozenset(
    {
        RunState.MERGE_DECISION_PUBLISHED,
        RunState.BUILT,
        RunState.INTEGRATION_TESTED,
        RunState.COVERAGE_CHECKED,
        RunState.CONTAINER_BUILT,
        RunState.SBOM_GENERATED,
        RunState.IMAGE_SCANNED,
        RunState.SIGNED,
        RunState.PUBLISHED,
    }
)

# Stage -> uploaded report files the supply-chain collector consumes.
PHASE_B_EVIDENCE_FILES: dict[str, tuple[str, ...]] = {
    "container_build": ("image-digest.txt",),
    "sbom_generate": ("sbom.json",),
    "sign_attest": ("image.sig", "image-attestation.json"),
}

# PipelineSpec.thresholds key for the coverage gate.
COVERAGE_THRESHOLD_KEY = "coverage_percent"

MERGE_DECISION_AUDIT_EVENT = "merge_decision_published"
PUBLISH_CHECK_NAME = "ci-agent publish decision"

LOGGER = logging.getLogger("ci_agent.orchestrator.phase_b")

_DEAD_STATES: frozenset[RunState] = frozenset(
    {RunState.FAILED, RunState.ERROR, PHASE_B_SUCCESS_STATE}
)


class PhaseBOrchestrator:
    """Drive the Section 5.2 supply-chain flow for approved Phase A runs."""

    def __init__(
        self,
        *,
        audit_store: AuditStore,
        session_factory: sessionmaker[Session],
        project_registry: ProjectRegistry,
        planner: Any,
        pdp: PolicyDecisionPoint,
        adapter: RunnerAdapter | AdapterRouter,
        github_client: Any,
        concurrency_guard: ConcurrencyGuard,
        policy_spec_version: str,
        sbom_service: SBOMService,
        signing_service: SigningService,
        exception_service: ExceptionService | None = None,
        # (run_id, stage_id) -> {filename: content}; wired in create_app to
        # the adapter's scan-artifact download using the Phase B dispatch
        # coordinates. Tests inject a deterministic fake.
        evidence_downloader: Callable[[str, str], dict[str, str]] | None = None,
        telemetry_emitter: TelemetryEmitter | None = None,
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
        self._sbom_service = sbom_service
        self._signing_service = signing_service
        self._exception_service = exception_service
        self._evidence_downloader = evidence_downloader
        # Batch 8, Task E: optional normalized-telemetry emitter (singleton on
        # app.state in production; None keeps standalone tests silent).
        self._telemetry = telemetry_emitter
        # Runtime mirrors of audited facts (per run): recorded SBOM format and
        # the real verification outcome for the recorded signature.
        self._sbom_format_by_run: dict[str, str] = {}
        self._signature_verified_by_run: dict[str, bool] = {}

    # ------------------------------------------------------------------ public

    def advance(self, run_id: str, trigger_event: dict[str, Any]) -> dict[str, Any] | None:
        """Advance one run through the Phase B flow (mirrors Phase A)."""
        event_type = str(trigger_event.get("type", ""))
        handlers = {
            "phase_b_start": self._on_start,
            "stage_transition": self._on_stage_transition,
        }
        handler = handlers.get(event_type)
        if handler is None:
            raise CallerError(f"unknown Phase B trigger event type {event_type!r}")
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
        self,
        run_id: str,
        stage_id: str,
        status: str,
        exit_code: int | None = None,
        coverage_percent: float | None = None,
    ) -> dict[str, Any] | None:
        """Observer callback: translate a Phase B stage outcome."""
        if stage_id.startswith("internal.") or stage_id == "workflow":
            return None
        return self.advance(
            run_id,
            {
                "type": "stage_transition",
                "stage_id": stage_id,
                "status": status,
                "exit_code": exit_code,
                "coverage_percent": coverage_percent,
            },
        )

    def start(self, run_id: str) -> dict[str, Any] | None:
        """Entry point wired to Phase A's approved-merge callback."""
        return self.advance(run_id, {"type": "phase_b_start"})

    # ------------------------------------------------------------- phase start

    def _on_start(self, run_id: str, _event: dict[str, Any]) -> dict[str, Any]:
        run = self._require_run(run_id)
        current = self._current_state(run_id)

        # HARD GATE (Section 5.2 — tested): Phase B never runs against
        # unapproved code. The run must sit at merge_decision_published AND
        # the audit trail's merge decision must say approved.
        if current is not RunState.MERGE_DECISION_PUBLISHED:
            self._audit(
                run_id,
                "phase_b_blocked",
                {
                    "reason": (
                        f"phase A state is {current.value if current else None!r}, not "
                        "merge_decision_published — Phase B never runs against unapproved code"
                    )
                },
            )
            raise CallerError(
                f"Phase B requires an approved merge decision; run is in "
                f"{current.value if current else None!r}"
            )
        if not self._phase_a_was_approved(run_id):
            self._audit(
                run_id,
                "phase_b_blocked",
                {"reason": "merge decision audit event is not approved"},
            )
            raise CallerError("Phase B requires an APPROVED merge decision")

        profile = self._registry.get_profile(run.project_id)
        spec_document = self._registry.get_pipeline_spec(run.project_id)
        # Batch 8 (folded-in Batch 7.1 Fix A): this is a spec RE-FETCH point —
        # the run was authorized against a spec hash persisted by Phase A, so
        # the re-fetched spec must hash to EXACTLY that value. A mismatch (a
        # mid-run registry edit) parks the run in ERROR (fail closed), audits
        # "spec_drift_detected" with both hashes, and never dispatches. The
        # persisted pipeline_spec_ref is an immutable record of what the run
        # was authorized against — it is never overwritten here.
        if not self._spec_drift_check(run_id, spec_document, point="phase_b_wave_1"):
            return {"state": RunState.ERROR.value, "reason": "spec drift detected"}
        spec = PipelineSpec.model_validate(spec_document)
        plan = self._planner.build_execution_plan(
            profile, spec, self._policy_version, run_id=run_id
        )

        wave_1 = self._wave_plan(plan, PHASE_B_WAVE_1_STAGES)
        adapter = self._runner_adapter(profile)
        artifact = adapter.compile(
            wave_1,
            metadata={"repository": run.repository, "source_sha": run.source_sha or ""},
        )
        dispatch_ref = adapter.dispatch(artifact, run_id)
        with self._session_factory() as session:
            persisted = session.get(RunRecord, run_id)
            assert persisted is not None, f"run {run_id!r} vanished mid-dispatch"
            persisted.phase_b_branch = dispatch_ref.branch
            persisted.phase_b_external_run_id = dispatch_ref.external_run_id
            session.commit()
        self._audit(
            run_id,
            "phase_b_dispatched",
            {
                "dispatch_branch": dispatch_ref.branch,
                "wave": "1",
                "stages": list(PHASE_B_WAVE_1_STAGES),
            },
        )
        return {"state": current.value, "phase_b": "dispatched", "wave": 1}

    def _phase_a_was_approved(self, run_id: str) -> bool:
        """The audit trail is the authority on the merge decision outcome."""
        for entry in reversed(self._audit_store.get_audit_trail(run_id)):
            if entry.event_type == MERGE_DECISION_AUDIT_EVENT:
                payload = json.loads(entry.payload_json)
                return bool(payload.get("approved"))
        return False

    @staticmethod
    def _wave_plan(plan: ExecutionPlan, wave_stages: tuple[str, ...]) -> ExecutionPlan:
        """Trim the full plan to one dispatch wave.

        depends_on edges are rewritten to reference only stages INSIDE the
        wave, so a wave-2 workflow has no dangling needs on Phase A / wave-1
        job ids. Stage ORDER (and therefore Phase-B-after-Phase-A needs
        chains when compiled whole) is preserved.
        """
        allowed = set(wave_stages)
        steps = [
            step.model_copy(
                update={"depends_on": [dep for dep in step.depends_on if dep in allowed]}
            )
            for step in plan.resolved_steps
            if step.stage_id in allowed
        ]
        return plan.model_copy(update={"resolved_steps": steps})

    # ------------------------------------------------------ stage transitions

    def _on_stage_transition(self, run_id: str, event: dict[str, Any]) -> dict[str, Any] | None:
        self._require_run(run_id)
        current = self._current_state(run_id)
        stage_id = str(event.get("stage_id", ""))
        status = str(event.get("status", ""))

        if current is None or current not in PHASE_B_ACTIVE_STATES:
            self._audit(
                run_id,
                "run_state_noop",
                {
                    "reason": (f"phase B inactive (state {current.value if current else None!r})"),
                    "stage_id": stage_id,
                },
            )
            return None
        if current in _DEAD_STATES:
            self._audit(
                run_id,
                "run_state_noop",
                {"reason": f"run already terminal ({current.value})", "stage_id": stage_id},
            )
            return {"state": current.value, "note": "run already terminal"}

        target = PHASE_B_STAGE_TO_RUN_STATE.get(stage_id)
        if target is None:
            self._audit(
                run_id,
                "run_state_noop",
                {"reason": f"stage {stage_id!r} is not a Phase B stage"},
            )
            return None

        if status != "passed":
            reason = f"phase B stage {stage_id!r} finished with status {status!r}"
            self._transition(run_id, current, RunState.FAILED, reason=reason)
            self._publish_outcome(run_id, approved=False, reasons=[reason])
            return {"state": RunState.FAILED.value, "reason": reason}

        # Evidence collection BEFORE the state lands (fail-closed: a missing
        # artifact surfaces as a control-plane error, never as fake-green).
        self._collect_stage_evidence(run_id, stage_id)

        if target is RunState.COVERAGE_CHECKED:
            blocked = self._coverage_gate_reason(run_id, event)
            if blocked is not None:
                self._transition(run_id, current, RunState.FAILED, reason=blocked)
                self._publish_outcome(run_id, approved=False, reasons=[blocked])
                return {"state": RunState.FAILED.value, "reason": blocked}

        assert_run_transition(current, target)
        self._transition(run_id, current, target, reason=f"phase B stage {stage_id!r} passed")

        if target is RunState.SIGNED:
            # Section 5.2 Stage 8: push only after the publish gate passes.
            return self._evaluate_publish_gate(run_id)

        if target is PHASE_B_SUCCESS_STATE:
            self._audit(run_id, "evidence_recorded", {"state": target.value})
            self._publish_outcome(run_id, approved=True, reasons=["phase B evidence recorded"])
            return {"state": target.value}

        return {"state": target.value}

    # ------------------------------------------------------------- coverage

    def _coverage_gate_reason(self, run_id: str, event: dict[str, Any]) -> str | None:
        """Compare structured coverage output with PipelineSpec.thresholds.

        Returns None when the gate passes, else the failure reason. Fail-
        closed: configured threshold + missing coverage data = failure.
        """
        spec_document = self._registry.get_pipeline_spec(self._require_run(run_id).project_id)
        threshold = (spec_document.get("thresholds") or {}).get(COVERAGE_THRESHOLD_KEY)
        if threshold is None:
            return None  # nothing to enforce for this pipeline
        raw = event.get("coverage_percent")
        if raw is None:
            return (
                f"coverage gate: no coverage_percent in structured output but a "
                f"{COVERAGE_THRESHOLD_KEY} threshold ({threshold}) is configured — fail closed"
            )
        try:
            coverage = float(raw)
        except (TypeError, ValueError):
            return f"coverage gate: unparseable coverage value {raw!r} — fail closed"
        if coverage < float(threshold):
            return (
                f"coverage gate: {coverage}% is below the configured "
                f"{COVERAGE_THRESHOLD_KEY} threshold ({threshold})"
            )
        return None

    # -------------------------------------------------------- publish gate

    def _evaluate_publish_gate(self, run_id: str) -> dict[str, Any]:
        """Evaluate the publish gate on REAL evidence BEFORE wave-2 dispatch.

        The publish job is dispatched ONLY on PASS/WAIVED — a failing gate
        means the push step never exists in any runner (Section 5.2 Stage 8).
        """
        run = self._require_run(run_id)
        profile = self._registry.get_profile(run.project_id)
        spec_document = self._registry.get_pipeline_spec(run.project_id)
        # Batch 8 (folded-in Batch 7.1 Fix A): the wave-2 re-fetch point (the
        # batch spec calls this the publish-wave execution point). Same guard
        # as wave 1: a spec whose hash no longer matches the run's authorized
        # pipeline_spec_ref parks the run in ERROR and the publish wave is
        # NEVER dispatched (fail closed; the push job must not exist).
        if not self._spec_drift_check(run_id, spec_document, point="phase_b_wave_2"):
            return {"state": RunState.ERROR.value, "reason": "spec drift detected"}
        spec = PipelineSpec.model_validate(spec_document)
        plan = self._planner.build_execution_plan(
            profile, spec, self._policy_version, run_id=run_id
        )

        facts = self._publish_gate_facts(run, profile, spec_document, plan)
        decision = self._pdp.evaluate_gate("publish_gate", facts)
        if decision.decision is PolicyDecision.FAIL:
            reason = "publish_gate rejected: " + "; ".join(decision.reasons)
            self._transition(run_id, RunState.SIGNED, RunState.FAILED, reason=reason)
            self._publish_outcome(run_id, approved=False, reasons=decision.reasons)
            return {
                "state": RunState.FAILED.value,
                "reason": "publish_gate rejected",
                "exception_ids": decision.exception_ids,
            }

        wave_2 = self._wave_plan(plan, PHASE_B_WAVE_2_STAGES)
        adapter = self._runner_adapter(profile)
        artifact = adapter.compile(
            wave_2,
            metadata={"repository": run.repository, "source_sha": run.source_sha or ""},
        )
        wave2_ref = adapter.dispatch(artifact, run_id)
        # Batch 8 (folded-in Batch 7.1 Fix B): persist the wave-2 dispatch
        # coordinates on the RunRecord itself (same convention as the wave-1
        # columns) — queryable from the DB directly, not only from the audit
        # event payload below.
        with self._session_factory() as session:
            persisted = session.get(RunRecord, run_id)
            assert persisted is not None, f"run {run_id!r} vanished mid-dispatch"
            persisted.phase_b_wave2_branch = wave2_ref.branch
            persisted.phase_b_wave2_external_run_id = wave2_ref.external_run_id
            session.commit()
        waived = decision.decision is PolicyDecision.WAIVED
        self._audit(
            run_id,
            "phase_b_dispatched",
            {
                "wave": "2",
                "dispatch_branch": wave2_ref.branch,
                "stages": list(PHASE_B_WAVE_2_STAGES),
                "note": (
                    "publish_gate waived by exception " + ",".join(decision.exception_ids)
                    if waived
                    else "publish_gate passed"
                ),
                "exception_ids": decision.exception_ids,
            },
        )
        return {
            "state": RunState.SIGNED.value,
            "phase_b": "wave-2 dispatched",
            "waived": waived,
            "exception_ids": decision.exception_ids,
        }

    def _publish_gate_facts(
        self,
        run: RunRecord,
        profile: Any,
        spec_document: dict[str, Any],
        plan: ExecutionPlan,
    ) -> PolicyInputFacts:
        """Real image-scan findings + real artifact supply-chain facts."""
        evidence = SecurityEvidenceService(self._session_factory, self._audit_store)
        findings: list[dict[str, Any]] = [
            {
                "severity": record.severity,
                "scanner": record.scanner,
                "rule_id": record.rule_id,
                "component": record.component,
                "location": record.location,
                "disposition": record.disposition,
            }
            for record in evidence.get_findings_for_run(run.run_id)
        ]
        for flag in evidence.parser_warnings(run.run_id):
            findings.append(
                {
                    "severity": Severity.HIGH.value,
                    "scanner": str(flag["stage_id"]),
                    "rule_id": "parser_warning_unparseable_output",
                    "component": str(flag["stage_id"]),
                    "disposition": "open",
                }
            )
        # A failed image_scan with nothing parsed is a violation (fail-closed).
        with self._session_factory() as session:
            image_scan_failed = (
                session.execute(
                    select(StageExecutionRecord).where(
                        StageExecutionRecord.run_id == run.run_id,
                        StageExecutionRecord.stage_id == "image_scan",
                        StageExecutionRecord.status == "failed",
                    )
                )
                .scalars()
                .first()
            )
        if image_scan_failed is not None and not any(f["scanner"] == "trivy" for f in findings):
            findings.append(
                {
                    "severity": Severity.HIGH.value,
                    "scanner": "image_scan",
                    "rule_id": "scan_failed_without_parseable_findings",
                    "component": "image_scan",
                    "disposition": "open",
                }
            )

        artifact_record = self._sbom_service.artifact_for_run(run.run_id)
        sbom_format = self._sbom_format_by_run.get(run.run_id) if artifact_record else None
        artifacts = self._sbom_service.artifact_facts(artifact_record, sbom_format)
        if artifacts:
            # Section 8 "Verification" row: has_signature reflects a REAL
            # verification of the recorded signature — never a bare claim.
            artifacts[0]["has_signature"] = bool(artifacts[0]["has_signature"]) and bool(
                self._signature_verified_by_run.get(run.run_id, False)
            )
        return PolicyInputFacts(
            project_profile=profile.model_dump(mode="json"),
            pipeline_spec=spec_document,
            proposed_execution_plan=plan.model_dump(mode="json"),
            stage_id="publish_gate",
            findings=findings,
            artifacts=artifacts,
            run_id=run.run_id,
        )

    # ------------------------------------------------------- evidence collect

    def _collect_stage_evidence(self, run_id: str, stage_id: str) -> None:
        """Persist supply-chain evidence for a stage BEFORE it lands.

        container_build -> digest from REAL build output (never a tag);
        sbom_generate    -> Syft SBOM parse (SPDX/CycloneDX);
        sign_attest      -> signature + provenance references + REAL verify.
        Anything missing or unparseable raises -> the run parks in ERROR
        (fail closed), never a fake-green supply chain.
        """
        if stage_id not in PHASE_B_EVIDENCE_FILES:
            return
        contents = self._download(run_id, stage_id)
        if stage_id == "container_build":
            raw_digest = (contents.get("image-digest.txt") or "").strip()
            if not raw_digest:
                raise TagOnlyDigestError(
                    "container_build produced no image digest — refusing to "
                    "record a tag-based identity"
                )
            spec_document = self._registry.get_pipeline_spec(self._require_run(run_id).project_id)
            destinations = list(spec_document.get("artifact_destinations") or [])
            # The allowlist governs registry HOSTS ("ghcr.io"), while the
            # destination carries the full repository path — record the host
            # so artifact_policy.rego's exact allowlist match is correct.
            registry = destinations[0].split("/")[0] if destinations else "local-archive"
            self._sbom_service.record_artifact(run_id, digest=raw_digest, registry=registry)
            self._audit(run_id, "artifact_digest_recorded", {"stage_id": stage_id})
        elif stage_id == "sbom_generate":
            raw_sbom = contents.get("sbom.json") or ""
            sbom = self._sbom_service.parse_syft_output(  # SBOMParseError -> ERROR
                raw_sbom, run_id=run_id
            )
            record = self._sbom_service.artifact_for_run(run_id)
            if record is None:
                from ci_agent.supplychain.sbom_service import SBOMParseError

                raise SBOMParseError("SBOM produced but no artifact digest recorded for this run")
            self._sbom_service.record_artifact(
                run_id, digest=record.digest, registry=record.registry_host, sbom=sbom
            )
            self._sbom_format_by_run[run_id] = sbom.format
            self._audit(
                run_id,
                "sbom_recorded",
                # Summary facts only — never the full SBOM content.
                {"format": sbom.format, "component_count": sbom.component_count},
            )
        elif stage_id == "sign_attest":
            record = self._sbom_service.artifact_for_run(run_id)
            if record is None:
                raise LookupError("sign_attest ran but no artifact digest is recorded")
            bundle = contents.get("image.sig") or ""
            signature = self._signing_service.record_signature(record.digest, bundle, run_id=run_id)
            attestation = contents.get("image-attestation.json") or ""
            self._signing_service.record_provenance(record.digest, attestation, run_id=run_id)
            # REAL verification (Section 8 "Verification" row): a signature
            # that does not verify is treated as NO signature downstream —
            # the publish gate sees has_signature=False.
            verified = self._signing_service.verify_signature(record.digest)
            self._signature_verified_by_run[run_id] = verified
            self._audit(
                run_id,
                "signature_recorded",
                {
                    "signature_ref": signature.signature_ref,
                    "keyless": signature.keyless,
                    "verified": verified,
                },
            )

    def _download(self, run_id: str, stage_id: str) -> dict[str, str]:
        if self._evidence_downloader is None:
            return {}
        return self._evidence_downloader(run_id, stage_id) or {}

    # -------------------------------------------------------------- outcome

    def _publish_outcome(
        self, run_id: str, *, approved: bool, reasons: list[str] | None = None
    ) -> None:
        """Post the Phase B outcome as a Check Run (evidence-recorded/blocked)."""
        run = self._require_run(run_id)
        sha = run.source_sha
        if not sha:
            return
        title = "ci-agent publish decision: " + ("EVIDENCE RECORDED" if approved else "BLOCKED")
        summary = title + (("; Reasons: " + "; ".join(reasons)) if reasons else "")
        self._github.post_check_run(
            run.repository,
            sha,
            name=PUBLISH_CHECK_NAME,
            status="completed",
            conclusion="success" if approved else "failure",
            output={"title": title, "summary": summary},
        )
        self._audit(
            run_id,
            "phase_b_outcome_published",
            {"approved": approved, "check_name": PUBLISH_CHECK_NAME},
        )

    # ------------------------------------------------------------- plumbing
    # (mirrors PhaseAOrchestrator — dual-write, monotonic, fail-closed)

    def _spec_drift_check(self, run_id: str, spec_document: dict[str, Any], *, point: str) -> bool:
        """Folded-in Batch 7.1 Fix A: fail-closed spec-drift guard.

        Compares the canonical hash of the RE-FETCHED spec document against
        the ``pipeline_spec_ref`` persisted on the RunRecord (the immutable
        record of what the run was authorized against — written once by Phase
        A at initial dispatch and never overwritten afterwards).

        Returns True when the run may proceed. On mismatch: transitions the
        run to ERROR (fail closed), appends a ``spec_drift_detected`` audit
        event carrying BOTH hashes, and returns False — the caller must NOT
        dispatch. A NULL persisted hash (legacy pre-Batch-8 rows that never
        got an initial write) is treated as the initial write, not drift.
        """
        actual_hash = _canonical_spec_hash(spec_document)
        with self._session_factory() as session:
            persisted = session.get(RunRecord, run_id)
            assert persisted is not None, f"run {run_id!r} vanished mid-planning"
            expected_hash = persisted.pipeline_spec_ref
            if expected_hash is None:
                # Initial write for a legacy row (no Phase A authorization
                # hash was recorded): record it; there is nothing to compare.
                persisted.pipeline_spec_ref = actual_hash
                session.commit()
                self._audit(
                    run_id,
                    "pipeline_spec_ref_backfilled",
                    {"point": point, "hash": actual_hash},
                )
                return True
        if expected_hash != actual_hash:
            self._transition(
                run_id,
                self._current_state(run_id),
                RunState.ERROR,
                reason=(
                    f"spec drift detected at {point}: the registered pipeline "
                    "spec changed after the run was authorized — refusing to "
                    "dispatch against an unauthorized spec"
                ),
            )
            self._audit(
                run_id,
                "spec_drift_detected",
                {
                    "point": point,
                    "expected_hash": expected_hash,
                    "actual_hash": actual_hash,
                },
            )
            return False
        return True

    def _runner_adapter(self, profile: Any) -> RunnerAdapter:
        """Select the runner adapter for a project (Batch 8 multi-runner).

        Same contract as PhaseAOrchestrator._runner_adapter: with an
        AdapterRouter wired, an unknown/unregistered runner raises
        UnknownRunnerError at plan time and the run parks in ERROR (fail
        closed); a plain adapter (tests) passes through unchanged.
        """
        if isinstance(self._adapter, AdapterRouter):
            return self._adapter.adapter_for_profile(select_runner_name(profile))
        return self._adapter

    def _emit_run_event(self, run_id: str, status: StageStatus, event_type: str) -> None:
        """Emit one normalized pipeline-run telemetry event (Batch 8, Task E).

        Phase B mirrors Phase A's emitter wiring so a run's terminal state is
        emitted whichever phase ends it (documented in NOTES.md). Telemetry is
        never a failure point: the emitter never raises and this wrapper
        additionally absorbs model-construction/profile-lookup errors.
        """
        if self._telemetry is None:
            return
        try:
            run = self._require_run(run_id)
            try:
                runner = self._registry.get_profile(run.project_id).runner
            except Exception:
                runner = "unknown"
            self._telemetry.emit_pipeline_run(
                PipelineRunEvent(
                    event_type=event_type,
                    pipeline_name=run.project_id,
                    run_id=run_id,
                    runner=runner,
                    status=status,
                    attributes={"phase": "phase_b"},
                )
            )
        except Exception:
            LOGGER.debug("run telemetry emission failed for %s", run_id, exc_info=True)

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
        assert_run_transition(current, target)
        self._write_state(run_id, current, target)
        payload: dict[str, Any] = {
            "from": current.value if current else None,
            "to": target.value,
        }
        if reason:
            payload["reason"] = reason
        self._audit(run_id, "run_state_transition", payload)
        # Batch 8, Task E: emit the run's terminal state from Phase B too
        # (EVIDENCE_RECORDED is the success terminal for runs that complete
        # the supply chain flow; StageStatus has no "error" member, so ERROR
        # maps to FAILED — the authoritative state stays in the audit trail).
        if target is PHASE_B_SUCCESS_STATE:
            self._emit_run_event(run_id, StageStatus.PASSED, "run_terminal")
        elif target in (RunState.FAILED, RunState.ERROR):
            self._emit_run_event(run_id, StageStatus.FAILED, "run_terminal")

    def _write_state(self, run_id: str, current: RunState | None, target: RunState) -> None:
        with self._session_factory() as session:
            run = session.get(RunRecord, run_id)
            assert run is not None, f"run {run_id!r} vanished mid-transition"
            persisted_raw = run.current_state
            if persisted_raw != (current.value if current else None):
                assert_run_transition(RunState(persisted_raw) if persisted_raw else None, target)
            run.current_state = target.value
            run.updated_at = utcnow()
            session.commit()

    def _park_in_error(self, run_id: str, detail: str) -> None:
        """Fail closed: unexpected control-plane errors park the run in ERROR."""
        try:
            current = self._current_state(run_id)
            if current in _DEAD_STATES:
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

    def _audit(self, run_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self._audit_store.append_event(run_id, event_type, payload)


__all__ = [
    "COVERAGE_THRESHOLD_KEY",
    "PHASE_B_ACTIVE_STATES",
    "PHASE_B_STAGES",
    "PHASE_B_STAGE_TO_RUN_STATE",
    "PHASE_B_WAVE_1_STAGES",
    "PHASE_B_WAVE_2_STAGES",
    "PUBLISH_CHECK_NAME",
    "PhaseBOrchestrator",
]
