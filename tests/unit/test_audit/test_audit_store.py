"""Unit tests for the AuditStore (Batch 2, Task A)."""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select

from ci_agent.audit.audit_store import AuditStore, canonical_json, compute_entry_hash
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.db.models import GENESIS_PREV_HASH, AuditLogEntry


class TestCreateRun:
    def test_create_and_get_run_round_trip(self, audit_store: AuditStore) -> None:
        created = audit_store.create_run(
            run_id="run-1",
            project_id="example-org/payments-api",
            repository="example-org/payments-api",
            trigger_type="pull_request",
            source_sha="abc123",
        )

        fetched = audit_store.get_run("run-1")
        assert fetched is not None
        assert fetched.run_id == "run-1"
        assert fetched.project_id == "example-org/payments-api"
        assert fetched.repository == "example-org/payments-api"
        assert fetched.trigger_type == "pull_request"
        assert fetched.source_sha == "abc123"
        assert fetched.status == "accepted"
        assert fetched.created_at == created.created_at

    def test_get_run_unknown_returns_none(self, audit_store: AuditStore) -> None:
        assert audit_store.get_run("nope") is None

    @pytest.mark.parametrize("bad_trigger", ["fork_bomb", "", "PUSH"])
    def test_invalid_trigger_type_rejected(self, audit_store: AuditStore, bad_trigger: str) -> None:
        with pytest.raises(ValueError, match="trigger_type"):
            audit_store.create_run("run-x", "p", "r", bad_trigger)


class TestAppendOnlyAuditChain:
    def test_first_entry_uses_genesis_prev_hash(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        entry = audit_store.append_event("run-1", "run_created", {"sha": "abc"})

        assert entry.prev_hash == GENESIS_PREV_HASH
        assert len(entry.entry_hash) == 64

    def test_entries_chain_together(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        first = audit_store.append_event("run-1", "webhook_received", {"n": 1})
        second = audit_store.append_event("run-1", "run_created", {"n": 2})
        third = audit_store.append_event("run-1", "policy_decision", {"n": 3})

        assert second.prev_hash == first.entry_hash
        assert third.prev_hash == second.entry_hash

    def test_verify_chain_true_for_intact_trail(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        for i in range(5):
            audit_store.append_event("run-1", f"event_{i}", {"seq": i})

        assert audit_store.verify_chain("run-1") is True

    def test_verify_chain_true_for_unknown_run(self, audit_store: AuditStore) -> None:
        # Vacuously intact: there is nothing to verify.
        assert audit_store.verify_chain("ghost") is True

    def test_verify_chain_detects_tampered_payload(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        audit_store.append_event("run-1", "run_created", {"sha": "abc"})
        audit_store.append_event("run-1", "webhook_received", {"sha": "def"})

        # Tamper with the DB row directly, bypassing the store API.
        with audit_store._session_factory() as session:
            row = session.execute(
                select(AuditLogEntry).where(
                    AuditLogEntry.run_id == "run-1",
                    AuditLogEntry.event_type == "run_created",
                )
            ).scalar_one()
            row.payload_json = canonical_json({"sha": "HACKED"})
            session.commit()

        assert audit_store.verify_chain("run-1") is False

    def test_verify_chain_detects_tampered_entry_hash(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        audit_store.append_event("run-1", "run_created", {"sha": "abc"})

        with audit_store._session_factory() as session:
            row = session.execute(select(AuditLogEntry)).scalar_one()
            row.entry_hash = "0" * 64
            session.commit()

        assert audit_store.verify_chain("run-1") is False

    def test_verify_chain_detects_broken_link(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        audit_store.append_event("run-1", "a", {})
        audit_store.append_event("run-1", "b", {})

        with audit_store._session_factory() as session:
            rows = list(session.execute(select(AuditLogEntry).order_by(AuditLogEntry.id)).scalars())
            rows[1].prev_hash = "f" * 64  # sever the chain link
            session.commit()

        assert audit_store.verify_chain("run-1") is False

    def test_trails_are_isolated_per_run(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        audit_store.create_run("run-2", "p", "r", "push")
        audit_store.append_event("run-1", "only_run_1", {})

        assert len(audit_store.get_audit_trail("run-1")) == 1
        assert len(audit_store.get_audit_trail("run-2")) == 0
        assert audit_store.verify_chain("run-2") is True


class TestComputeEntryHashFormula:
    def test_matches_spec_formula(self) -> None:
        created_at = datetime(2026, 9, 3, 10, 0, 0)
        payload_json = canonical_json({"b": 2, "a": 1})

        expected_first = compute_entry_hash(
            GENESIS_PREV_HASH, payload_json, "run_created", created_at
        )
        expected_second = compute_entry_hash(expected_first, payload_json, "next", created_at)

        # Deterministic and chained.
        assert expected_first == compute_entry_hash(
            GENESIS_PREV_HASH, payload_json, "run_created", created_at
        )
        assert expected_second != expected_first
        # Changing any component changes the hash.
        assert (
            compute_entry_hash(GENESIS_PREV_HASH, payload_json, "other", created_at)
            != expected_first
        )

    def test_canonical_json_is_stable_and_sorted(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
        assert " " not in canonical_json({"a": 1})


class TestDeliveryDedupe:
    def test_unseen_delivery_not_processed(self, audit_store: AuditStore) -> None:
        assert audit_store.is_delivery_processed("d-1") is False

    def test_mark_then_check(self, audit_store: AuditStore) -> None:
        audit_store.mark_delivery_processed("d-1", "run-1")

        assert audit_store.is_delivery_processed("d-1") is True

    def test_mark_is_idempotent(self, audit_store: AuditStore) -> None:
        audit_store.mark_delivery_processed("d-1", "run-1")
        audit_store.mark_delivery_processed("d-1", "run-1")  # must not raise

        assert audit_store.is_delivery_processed("d-1") is True


class TestRunRecordTimestamps:
    def test_updated_at_defaults_set(self, session_factory) -> None:
        store = AuditStore(session_factory)
        run = store.create_run("run-1", "p", "r", "manual")

        assert isinstance(run.updated_at, datetime)
        assert isinstance(run.created_at, datetime)

    def test_tables_exist_via_metadata(self, memory_engine) -> None:
        inspector = sa_inspect(memory_engine)
        tables = set(inspector.get_table_names())
        assert {"run_records", "audit_log_entries", "processed_deliveries"} <= tables


class TestAuditAppendOrder:
    def test_trail_preserves_append_order(self, audit_store: AuditStore) -> None:
        audit_store.create_run("run-1", "p", "r", "push")
        for i in range(10):
            audit_store.append_event("run-1", f"event_{i}", {"i": i})

        trail = audit_store.get_audit_trail("run-1")
        assert [entry.event_type for entry in trail] == [f"event_{i}" for i in range(10)]
        ids = [entry.id for entry in trail]
        assert ids == sorted(ids)


def test_no_global_session_is_used() -> None:
    """Two stores built on separate engines must be fully isolated (no global session)."""
    engine_a = create_engine("sqlite:///:memory:")
    engine_b = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine_a)
    Base.metadata.create_all(engine_b)

    store_a = AuditStore(get_session_factory(engine_a))
    store_b = AuditStore(get_session_factory(engine_b))
    store_a.create_run("run-a", "p", "r", "push")

    assert store_a.get_run("run-a") is not None
    assert store_b.get_run("run-a") is None
    for engine in (engine_a, engine_b):
        engine.dispose()
