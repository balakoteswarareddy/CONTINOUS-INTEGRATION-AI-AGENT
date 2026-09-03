"""RunState machine tests (Batch 5): exact enum, adjacency, monotonicity."""

from __future__ import annotations

from itertools import pairwise

import pytest

from ci_agent.orchestrator.run_state import (
    ALLOWED_RUN_TRANSITIONS,
    TERMINAL_RUN_STATES,
    InvalidRunTransitionError,
    RunState,
    assert_run_transition,
)

EXPECTED_STATES = {
    "TRIGGER_VALIDATED",
    "CHECKED_OUT",
    "BASELINE_VALIDATED",
    "LINTED",
    "SAST_DONE",
    "TESTS_DONE",
    "SECURITY_CHECKED",
    "POLICY_GATE_EVAL",
    "AWAITING_APPROVAL",
    "APPROVED",
    "REJECTED",
    "MERGE_DECISION_PUBLISHED",
    # --- Phase B (Batch 7, Section 5.2 nine-stage flow) ---------------------
    "BUILT",
    "INTEGRATION_TESTED",
    "COVERAGE_CHECKED",
    "CONTAINER_BUILT",
    "SBOM_GENERATED",
    "IMAGE_SCANNED",
    "SIGNED",
    "PUBLISHED",
    "EVIDENCE_RECORDED",
    "FAILED",
    "ERROR",
}


def test_enum_has_exactly_the_specified_states() -> None:
    assert {member.name for member in RunState} == EXPECTED_STATES
    assert len(RunState) == 23


def test_terminal_states_have_no_outgoing_transitions() -> None:
    """FAILED/ERROR are absolute terminals; merge_decision_published's only
    outgoing edge is the Phase B gateway (covered separately below)."""
    from ci_agent.orchestrator.run_state import RunState

    for terminal in TERMINAL_RUN_STATES - {RunState.MERGE_DECISION_PUBLISHED}:
        assert ALLOWED_RUN_TRANSITIONS[terminal] == frozenset()


def test_merge_decision_published_only_leads_to_phase_b() -> None:
    """Batch 7: an APPROVED merge decision is the ONLY Phase B gateway.

    No Phase A or error state may reach BUILT — Phase B never runs against
    unapproved code (Section 5.2; enforced by PhaseBOrchestrator.start and
    tested there end-to-end).

    Batch 8: MERGE_DECISION_PUBLISHED additionally carries fail-closed
    FAILED/ERROR outgoing edges (spec-drift guard + latent wave-1-failure
    gap; NOTES.md) — the BUILT gateway itself is unchanged: it remains the
    ONLY success edge and no other state may reach BUILT.
    """
    assert ALLOWED_RUN_TRANSITIONS[RunState.MERGE_DECISION_PUBLISHED] == frozenset(
        {RunState.BUILT, RunState.FAILED, RunState.ERROR}
    )
    for state, targets in ALLOWED_RUN_TRANSITIONS.items():
        if state in (None, RunState.MERGE_DECISION_PUBLISHED):
            continue
        assert RunState.BUILT not in targets


def test_happy_path_is_fully_connected() -> None:
    happy = [
        None,
        RunState.TRIGGER_VALIDATED,
        RunState.CHECKED_OUT,
        RunState.BASELINE_VALIDATED,
        RunState.LINTED,
        RunState.SAST_DONE,
        RunState.TESTS_DONE,
        RunState.SECURITY_CHECKED,
        RunState.POLICY_GATE_EVAL,
        RunState.APPROVED,
        RunState.MERGE_DECISION_PUBLISHED,
    ]
    for current, target in pairwise(happy):
        assert_run_transition(current, target)


def test_parallel_sast_tests_orderings_both_allowed() -> None:
    assert_run_transition(RunState.LINTED, RunState.SAST_DONE)
    assert_run_transition(RunState.LINTED, RunState.TESTS_DONE)
    assert_run_transition(RunState.SAST_DONE, RunState.TESTS_DONE)
    assert_run_transition(RunState.TESTS_DONE, RunState.SAST_DONE)


def test_backwards_transition_raises() -> None:
    with pytest.raises(InvalidRunTransitionError):
        assert_run_transition(RunState.LINTED, RunState.CHECKED_OUT)


def test_skip_ahead_raises() -> None:
    with pytest.raises(InvalidRunTransitionError):
        assert_run_transition(RunState.TRIGGER_VALIDATED, RunState.TESTS_DONE)


def test_published_to_failed_now_allowed_fail_closed() -> None:
    """Batch 8: merge_decision_published -> FAILED/ERROR are legal (fail closed).

    Required by the spec-drift guard (a mid-run registry edit parks the run in
    ERROR at Phase B start) and by wave-1 stage failures observed before BUILT
    lands. Success from this state still leads ONLY to BUILT; backwards
    transitions remain illegal (monotonic machine).
    """
    assert_run_transition(RunState.MERGE_DECISION_PUBLISHED, RunState.FAILED)
    assert_run_transition(RunState.MERGE_DECISION_PUBLISHED, RunState.ERROR)
    assert_run_transition(RunState.MERGE_DECISION_PUBLISHED, RunState.BUILT)
    with pytest.raises(InvalidRunTransitionError):
        assert_run_transition(RunState.MERGE_DECISION_PUBLISHED, RunState.CHECKED_OUT)
    with pytest.raises(InvalidRunTransitionError):
        assert_run_transition(RunState.MERGE_DECISION_PUBLISHED, RunState.EVIDENCE_RECORDED)


def test_awaiting_approval_paths() -> None:
    assert_run_transition(RunState.AWAITING_APPROVAL, RunState.APPROVED)
    assert_run_transition(RunState.AWAITING_APPROVAL, RunState.REJECTED)
    with pytest.raises(InvalidRunTransitionError):
        assert_run_transition(RunState.APPROVED, RunState.AWAITING_APPROVAL)


def test_error_message_contains_both_states() -> None:
    # Failure exits are allowed from every active state; skipping BACKWARDS
    # from an approval pause to a build stage is not.
    assert_run_transition(RunState.LINTED, RunState.FAILED)
    with pytest.raises(InvalidRunTransitionError, match=r"awaiting_approval.*checked_out"):
        assert_run_transition(RunState.AWAITING_APPROVAL, RunState.CHECKED_OUT)


def test_none_entry_state_allowed() -> None:
    assert_run_transition(None, RunState.TRIGGER_VALIDATED)
    with pytest.raises(InvalidRunTransitionError):
        assert_run_transition(None, RunState.CHECKED_OUT)
