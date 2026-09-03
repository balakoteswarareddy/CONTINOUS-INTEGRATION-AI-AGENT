"""Unit tests for the replay guard (Batch 2, Task B)."""

from __future__ import annotations

from ci_agent.ingress.replay_guard import ReplayGuard


class TestReplayGuard:
    def test_first_delivery_is_not_a_duplicate(self, audit_store) -> None:
        guard = ReplayGuard(audit_store)

        assert guard.is_duplicate("delivery-1") is False

    def test_marked_delivery_is_a_duplicate(self, audit_store) -> None:
        guard = ReplayGuard(audit_store)
        guard.mark_processed("delivery-1", "run-1")

        assert guard.is_duplicate("delivery-1") is True

    def test_deliveries_are_independent(self, audit_store) -> None:
        guard = ReplayGuard(audit_store)
        guard.mark_processed("delivery-1", "run-1")

        assert guard.is_duplicate("delivery-2") is False

    def test_remarking_is_idempotent(self, audit_store) -> None:
        guard = ReplayGuard(audit_store)
        guard.mark_processed("delivery-1", "run-1")
        guard.mark_processed("delivery-1", "run-1")

        assert guard.is_duplicate("delivery-1") is True
