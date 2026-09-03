"""Spec-drift guard + wave-2 coordinate persistence (Batch 8 folded-in
Batch 7.1 Fixes A and B).

Fix A: at EVERY spec re-fetch point with a plan rebuild (Phase B wave 1 in
``PhaseBOrchestrator.start`` and wave 2 in ``_evaluate_publish_gate``), the
re-fetched spec's canonical hash must equal the ``pipeline_spec_ref`` the run
was authorized against. A mid-run registry edit parks the run in ERROR,
audits ``spec_drift_detected`` with BOTH hashes, never dispatches, and never
overwrites the persisted hash. Phase A's initial dispatch is the FIRST write
(no comparison — documented in the code).

Fix B: the wave-2 (publish wave) dispatch coordinates are persisted on the
RunRecord (``phase_b_wave2_branch`` / ``phase_b_wave2_external_run_id``),
retrievable from the DB directly — not only from the audit event payload.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from tests.unit.test_orchestrator.test_phase_b_orchestrator import (  # noqa: F401
    REPO,
    _approve_phase_a,
    _drive_wave_1,
    _happy_downloader,
    env,
)

from ci_agent.adapters.base import CompiledArtifact, DispatchRef
from ci_agent.db.models import RunRecord
from ci_agent.orchestrator.phase_a_orchestrator import _canonical_spec_hash
from ci_agent.orchestrator.phase_b_orchestrator import PhaseBOrchestrator


def _mutate_registered_spec(env: dict) -> str:
    """Simulate a mid-run registry edit: register a NEW spec version.

    The edit changes an inert descriptive field (project_name) so the hash
    changes WITHOUT altering wave-1 execution semantics — the drift itself is
    the failure under test, not a policy difference.
    Returns the canonical hash of the mutated document (the 'actual' hash).
    """
    document = env["registry"].get_pipeline_spec(REPO)
    document["project_name"] = document.get("project_name", "") + " (mid-run edit)"
    env["registry"].register_pipeline_spec(REPO, document)
    return _canonical_spec_hash(document)


def _authorize_phase_a(env: dict, run_id: str) -> str:
    """Complete Phase A AND record the spec authorization Phase A writes.

    Mirrors what PhaseAOrchestrator._on_run_created does at initial dispatch:
    the run's pipeline_spec_ref is the FIRST write of the hash of the spec
    the run was authorized against.
    """
    _approve_phase_a(env, run_id, approved=True)
    spec_document = env["registry"].get_pipeline_spec(REPO)
    authorized_hash = _canonical_spec_hash(spec_document)
    with env["session_factory"]() as session:
        run = session.get(RunRecord, run_id)
        assert run is not None
        run.pipeline_spec_ref = authorized_hash
        session.commit()
    return authorized_hash


def _drift_event(env: dict, run_id: str) -> dict[str, Any]:
    trail = env["audit_store"].get_audit_trail(run_id)
    events = [json.loads(e.payload_json) for e in trail if e.event_type == "spec_drift_detected"]
    assert len(events) == 1
    return events[0]


class TestFixAWaveOneDrift:
    def test_drift_at_wave_1_parks_error_and_never_dispatches(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        authorized = _authorize_phase_a(env, "run-drift-1")
        actual = _mutate_registered_spec(env)

        result = orchestrator.start("run-drift-1")

        # (a) run transitions to ERROR (fail closed).
        assert result == {"state": "error", "reason": "spec drift detected"}
        with env["session_factory"]() as session:
            run = session.get(RunRecord, "run-drift-1")
            assert run.current_state == "error"
            # (d) pipeline_spec_ref was NOT overwritten — still the authorized
            # hash, never the drifted one.
            assert run.pipeline_spec_ref == authorized
            assert run.pipeline_spec_ref != actual
            assert run.phase_b_branch is None  # wave 1 never dispatched

        # (b) no dispatch call was made.
        assert env["adapter"].dispatches == []

        # (c) the spec_drift_detected audit event exists with BOTH hashes.
        event = _drift_event(env, "run-drift-1")
        assert event["point"] == "phase_b_wave_1"
        assert event["expected_hash"] == authorized
        assert event["actual_hash"] == actual

    def test_no_drift_at_wave_1_dispatches_normally(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        authorized = _authorize_phase_a(env, "run-nodrift-1")

        result = orchestrator.start("run-nodrift-1")

        assert result["phase_b"] == "dispatched"
        assert env["adapter"].dispatches == ["run-nodrift-1"]
        with env["session_factory"]() as session:
            run = session.get(RunRecord, "run-nodrift-1")
            assert run.pipeline_spec_ref == authorized  # untouched


class TestFixAWaveTwoDrift:
    def test_drift_at_wave_2_parks_error_and_never_dispatches_wave_2(self, env) -> None:
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        authorized = _authorize_phase_a(env, "run-drift-2")
        assert orchestrator.start("run-drift-2")["phase_b"] == "dispatched"

        actual = _mutate_registered_spec(env)
        # Driving wave 1 to sign_attest passed triggers the publish gate —
        # whose spec re-fetch is the wave-2 drift check point.
        result = _drive_wave_1(orchestrator, "run-drift-2")

        assert result == {"state": "error", "reason": "spec drift detected"}
        with env["session_factory"]() as session:
            run = session.get(RunRecord, "run-drift-2")
            assert run.current_state == "error"
            assert run.pipeline_spec_ref == authorized
            assert run.pipeline_spec_ref != actual
            # Wave 1 dispatched; wave 2 (publish) NEVER did.
            assert run.phase_b_wave2_branch is None
        assert env["adapter"].dispatches == ["run-drift-2"]

        event = _drift_event(env, "run-drift-2")
        assert event["point"] == "phase_b_wave_2"
        assert event["expected_hash"] == authorized
        assert event["actual_hash"] == actual


class TestFixALegacyBackfill:
    def test_legacy_run_without_spec_ref_is_backfilled_not_drift(self, env) -> None:
        """A run whose pipeline_spec_ref was never written (pre-Batch-8 row)
        gets the documented first-write backfill at Phase B start — not a
        false drift failure."""
        orchestrator = env["make_orchestrator"](downloader=_happy_downloader)
        _approve_phase_a(env, "run-legacy-1")  # no pipeline_spec_ref write

        result = orchestrator.start("run-legacy-1")

        assert result["phase_b"] == "dispatched"
        expected = _canonical_spec_hash(env["registry"].get_pipeline_spec(REPO))
        with env["session_factory"]() as session:
            run = session.get(RunRecord, "run-legacy-1")
            assert run.pipeline_spec_ref == expected
        event_types = [e.event_type for e in env["audit_store"].get_audit_trail("run-legacy-1")]
        assert "pipeline_spec_ref_backfilled" in event_types
        assert "spec_drift_detected" not in event_types


class TestFixBWaveTwoCoordinates:
    def test_wave_2_coordinates_persisted_on_run_record(self, env) -> None:
        """After a full Phase B run (mocked adapter), the wave-2 dispatch
        coordinates are retrievable from the DB directly."""

        class _WaveTrackingAdapter:
            """Fake adapter returning distinct external ids per dispatch."""

            def __init__(self) -> None:
                self.dispatches: list[str] = []

            def compile(
                self, plan: Any, metadata: dict[str, str] | None = None
            ) -> CompiledArtifact:
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
                    external_run_id=f"ext-{len(self.dispatches)}",
                )

        adapter = _WaveTrackingAdapter()
        orchestrator = PhaseBOrchestrator(
            audit_store=env["audit_store"],
            session_factory=env["session_factory"],
            project_registry=env["registry"],
            planner=_planner_from_env(env),
            pdp=env["pdp"],
            adapter=adapter,  # type: ignore[arg-type]
            github_client=env["github"],  # type: ignore[arg-type]
            concurrency_guard=_guard_from_env(env),
            policy_spec_version=env["policy_spec"].policy_version,
            sbom_service=env["sbom_service"],
            signing_service=env["signing_service"],
            exception_service=env["exceptions"],
            evidence_downloader=_happy_downloader,
        )

        _authorize_phase_a(env, "run-wave2-1")
        assert orchestrator.start("run-wave2-1")["phase_b"] == "dispatched"
        result = _drive_wave_1(orchestrator, "run-wave2-1")
        assert result is not None and result["phase_b"] == "wave-2 dispatched"

        with env["session_factory"]() as session:
            run = session.get(RunRecord, "run-wave2-1")
            # Wave 1 coordinates (Batch 7 columns) — and now wave 2 (Fix B),
            # straight from the DB, not from the audit payload.
            assert run.phase_b_branch == "ci-agent/run-wave2-1"
            assert run.phase_b_external_run_id == "ext-1"
            assert run.phase_b_wave2_branch == "ci-agent/run-wave2-1"
            assert run.phase_b_wave2_external_run_id == "ext-2"

        # The audit payload still carries the dispatch (unchanged behaviour).
        dispatched = [
            json.loads(e.payload_json)
            for e in env["audit_store"].get_audit_trail("run-wave2-1")
            if e.event_type == "phase_b_dispatched"
        ]
        assert dispatched[-1]["wave"] == "2"
        assert dispatched[-1]["dispatch_branch"] == "ci-agent/run-wave2-1"


def _planner_from_env(env: dict) -> Any:
    """The env fixture does not expose the planner; rebuild it identically."""
    from ci_agent.planner.planner import Planner
    from ci_agent.planner.templates.template_registry import TemplateRegistry

    return Planner(TemplateRegistry(), env["policy_spec"])


def _guard_from_env(env: dict) -> Any:
    from ci_agent.reliability.concurrency_guard import ConcurrencyGuard

    return ConcurrencyGuard(3)


@pytest.mark.parametrize(
    "column",
    ["phase_b_wave2_branch", "phase_b_wave2_external_run_id"],
)
def test_wave2_columns_exist_on_the_orm_model(column: str) -> None:
    """Fix B: the wave-2 columns exist on RunRecord (migration 0006 mirrors)."""
    assert hasattr(RunRecord, column)
