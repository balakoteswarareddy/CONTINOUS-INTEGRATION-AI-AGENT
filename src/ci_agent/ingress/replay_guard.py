"""Replay / duplicate-delivery protection (Batch 2, Task B).

Thin wrapper over the AuditStore's ProcessedDelivery table — it deliberately
contains no DB logic of its own (Report Section 7.3: replay control via
delivery-ID dedupe; Section 10: duplicate handling must be idempotent).
"""

from __future__ import annotations

from ci_agent.audit.audit_store import AuditStore


class ReplayGuard:
    """Delivery-ID dedupe backed by the Audit Store."""

    def __init__(self, audit_store: AuditStore) -> None:
        self._audit_store = audit_store

    def is_duplicate(self, delivery_id: str) -> bool:
        """True if this delivery ID was already processed."""
        return self._audit_store.is_delivery_processed(delivery_id)

    def mark_processed(self, delivery_id: str, run_id: str) -> None:
        """Persist the delivery ID so replays are detected (idempotent)."""
        self._audit_store.mark_delivery_processed(delivery_id, run_id)
