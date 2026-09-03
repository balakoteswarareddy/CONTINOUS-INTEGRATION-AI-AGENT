"""Explicit pipeline run state machine (Batch 5; Report Section 10).

The control plane's authoritative position for every run is an explicit state
enum persisted on ``RunRecord.current_state`` and dual-written with the audit
log. Final state is NEVER inferred from free-form runner logs; the Execution
Observer feeds structured transitions into
:class:`ci_agent.orchestrator.phase_a_orchestrator.PhaseAOrchestrator.advance`,
which drives this machine.
"""

from __future__ import annotations

from enum import Enum


class RunState(str, Enum):
    """Pipeline run states, exactly as enumerated in the architecture report."""

    TRIGGER_VALIDATED = "trigger_validated"
    CHECKED_OUT = "checked_out"
    BASELINE_VALIDATED = "baseline_validated"
    LINTED = "linted"
    SAST_DONE = "sast_done"
    TESTS_DONE = "tests_done"
    SECURITY_CHECKED = "security_checked"
    POLICY_GATE_EVAL = "policy_gate_eval"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    MERGE_DECISION_PUBLISHED = "merge_decision_published"
    # --- Phase B (Batch 7; Report Section 5.2 nine-stage flow) ---------------
    # Phase B begins only from an APPROVED Phase A merge decision; it is
    # driven by PhaseBOrchestrator on the same RunRecord.current_state.
    BUILT = "built"
    INTEGRATION_TESTED = "integration_tested"
    COVERAGE_CHECKED = "coverage_checked"
    CONTAINER_BUILT = "container_built"
    SBOM_GENERATED = "sbom_generated"
    IMAGE_SCANNED = "image_scanned"
    SIGNED = "signed"
    PUBLISHED = "published"
    EVIDENCE_RECORDED = "evidence_recorded"
    FAILED = "failed"
    ERROR = "error"


class InvalidRunTransitionError(Exception):
    """Raised when a run state transition is not in the allowed adjacency."""

    def __init__(self, current: RunState | None, target: RunState) -> None:
        self.current = current
        self.target = target
        current_name = current.value if current is not None else None
        super().__init__(f"invalid run state transition: {current_name!r} -> {target.value!r}")


# Terminal states: no outgoing transitions. (Phase B's success terminal is
# EVIDENCE_RECORDED; MERGE_DECISION_PUBLISHED remains terminal *for Phase A* —
# its only outgoing edge, to BUILT, is exercised exclusively by the Phase B
# orchestrator on an APPROVED merge decision.)
TERMINAL_RUN_STATES: frozenset[RunState] = frozenset(
    {RunState.MERGE_DECISION_PUBLISHED, RunState.FAILED, RunState.ERROR}
)

# Phase B terminal/success states (Batch 7).
PHASE_B_SUCCESS_STATE: RunState = RunState.EVIDENCE_RECORDED

# Allowed state adjacency. The orchestrator maps observer stage outcomes and
# control-plane events onto these transitions; anything not listed here raises
# :class:`InvalidRunTransitionError` (monotonic pipeline: states never move
# backwards). ``sast`` and ``unit_tests`` run as parallel jobs, so their done
# states may arrive in either order — both orderings are permitted.
ALLOWED_RUN_TRANSITIONS: dict[RunState | None, frozenset[RunState]] = {
    None: frozenset({RunState.TRIGGER_VALIDATED}),
    RunState.TRIGGER_VALIDATED: frozenset({RunState.CHECKED_OUT, RunState.FAILED, RunState.ERROR}),
    RunState.CHECKED_OUT: frozenset({RunState.BASELINE_VALIDATED, RunState.FAILED, RunState.ERROR}),
    RunState.BASELINE_VALIDATED: frozenset({RunState.LINTED, RunState.FAILED, RunState.ERROR}),
    RunState.LINTED: frozenset(
        {RunState.SAST_DONE, RunState.TESTS_DONE, RunState.FAILED, RunState.ERROR}
    ),
    RunState.SAST_DONE: frozenset(
        {
            RunState.TESTS_DONE,
            RunState.SECURITY_CHECKED,
            RunState.FAILED,
            RunState.ERROR,
        }
    ),
    RunState.TESTS_DONE: frozenset(
        {
            RunState.SAST_DONE,
            RunState.SECURITY_CHECKED,
            RunState.FAILED,
            RunState.ERROR,
        }
    ),
    RunState.SECURITY_CHECKED: frozenset(
        {RunState.POLICY_GATE_EVAL, RunState.FAILED, RunState.ERROR}
    ),
    RunState.POLICY_GATE_EVAL: frozenset(
        {
            RunState.AWAITING_APPROVAL,
            RunState.APPROVED,
            RunState.FAILED,
            RunState.ERROR,
        }
    ),
    RunState.AWAITING_APPROVAL: frozenset(
        {RunState.APPROVED, RunState.REJECTED, RunState.FAILED, RunState.ERROR}
    ),
    RunState.APPROVED: frozenset({RunState.MERGE_DECISION_PUBLISHED, RunState.ERROR}),
    RunState.REJECTED: frozenset({RunState.MERGE_DECISION_PUBLISHED, RunState.ERROR}),
    # Batch 7: an APPROVED Phase A merge decision is the ONLY gateway into
    # Phase B (Section 5.2). No other state may enter BUILT — a failed or
    # rejected Phase A can never reach the supply-chain flow (tested).
    # Batch 8: FAILED/ERROR outgoing edges added — required by the spec-drift
    # guard (a mid-run registry edit at Phase B start must park the run in
    # ERROR, fail-closed) and consistent with every other active state having
    # fail edges; it also repairs a latent Batch 7 gap where a failing wave-1
    # stage observed while still at merge_decision_published could neither
    # transition to FAILED nor park in ERROR (documented in NOTES.md).
    RunState.MERGE_DECISION_PUBLISHED: frozenset({RunState.BUILT, RunState.FAILED, RunState.ERROR}),
    RunState.BUILT: frozenset({RunState.INTEGRATION_TESTED, RunState.FAILED, RunState.ERROR}),
    RunState.INTEGRATION_TESTED: frozenset(
        {RunState.COVERAGE_CHECKED, RunState.FAILED, RunState.ERROR}
    ),
    RunState.COVERAGE_CHECKED: frozenset(
        {RunState.CONTAINER_BUILT, RunState.FAILED, RunState.ERROR}
    ),
    RunState.CONTAINER_BUILT: frozenset({RunState.SBOM_GENERATED, RunState.FAILED, RunState.ERROR}),
    RunState.SBOM_GENERATED: frozenset({RunState.IMAGE_SCANNED, RunState.FAILED, RunState.ERROR}),
    RunState.IMAGE_SCANNED: frozenset({RunState.SIGNED, RunState.FAILED, RunState.ERROR}),
    RunState.SIGNED: frozenset({RunState.PUBLISHED, RunState.FAILED, RunState.ERROR}),
    RunState.PUBLISHED: frozenset({RunState.EVIDENCE_RECORDED, RunState.ERROR}),
    RunState.EVIDENCE_RECORDED: frozenset(),
    RunState.FAILED: frozenset(),
    RunState.ERROR: frozenset(),
}


def assert_run_transition(current: RunState | None, target: RunState) -> None:
    """Raise :class:`InvalidRunTransitionError` unless current -> target is legal."""
    if target not in ALLOWED_RUN_TRANSITIONS[current]:
        raise InvalidRunTransitionError(current, target)


__all__ = [
    "ALLOWED_RUN_TRANSITIONS",
    "PHASE_B_SUCCESS_STATE",
    "TERMINAL_RUN_STATES",
    "InvalidRunTransitionError",
    "RunState",
    "assert_run_transition",
]
