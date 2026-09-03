"""Audit Store repository (Batch 2, Task A; Report Sections 4.2 and 9).

Repository layer over :mod:`ci_agent.db.models`. One SQLAlchemy session per
call from the session factory, explicit commit, rollback on exception — no
global mutable session. The audit trail is append-only and hash-chained for
tamper-evidence.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.core.models.common import EventType
from ci_agent.db.models import (
    GENESIS_PREV_HASH,
    AuditLogEntry,
    ProcessedDelivery,
    RunRecord,
    utcnow,
)


def canonical_json(payload: dict[str, Any]) -> str:
    """Serialize ``payload`` deterministically (sorted keys, no whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_entry_hash(
    prev_hash: str, payload_json: str, event_type: str, created_at: datetime
) -> str:
    """Compute the tamper-evident hash of one audit entry (Batch 2 Task A).

    ``sha256(prev_hash + canonical_json(payload) + event_type +
    created_at.isoformat())`` — exactly the formula from the batch spec.
    """
    material = f"{prev_hash}{payload_json}{event_type}{created_at.isoformat()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditStore:
    """Repository for runs, the audit trail and delivery dedupe (Section 4.2/9)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ runs

    def create_run(
        self,
        run_id: str,
        project_id: str,
        repository: str,
        trigger_type: str,
        source_sha: str | None = None,
    ) -> RunRecord:
        """Insert a new RunRecord in ``accepted`` state (Section 4.2)."""
        if trigger_type not in {member.value for member in EventType}:
            valid = [m.value for m in EventType]
            raise ValueError(f"trigger_type must be one of {valid}; got {trigger_type!r}")
        now = utcnow()
        record = RunRecord(
            run_id=run_id,
            project_id=project_id,
            repository=repository,
            trigger_type=trigger_type,
            source_sha=source_sha,
            # status is the DEPRECATED insert-only column (Batch 5.1 Item 4):
            # intentionally not set here — the ORM default applies, and no
            # code path ever updates it afterwards.
            created_at=now,
            updated_at=now,
        )
        with self._session_factory() as session:
            session.add(record)
            session.commit()
            session.refresh(record)
        return record

    def get_run(self, run_id: str) -> RunRecord | None:
        """Fetch a run by ID, or ``None``."""
        with self._session_factory() as session:
            return session.get(RunRecord, run_id)

    # ---------------------------------------------------------------- audit

    def append_event(self, run_id: str, event_type: str, payload: dict[str, Any]) -> AuditLogEntry:
        """Append one hash-chained audit event for ``run_id``.

        The previous hash is the last entry's ``entry_hash`` for this run (or
        ``GENESIS`` for the first entry). The chain is append-only: nothing
        ever updates or deletes rows here.
        """
        with self._session_factory() as session:
            prev_hash = session.execute(
                select(AuditLogEntry.entry_hash)
                .where(AuditLogEntry.run_id == run_id)
                .order_by(AuditLogEntry.id.desc())
                .limit(1)
            ).scalar_one_or_none()
            created_at = utcnow()
            payload_json = canonical_json(payload)
            entry = AuditLogEntry(
                run_id=run_id,
                event_type=event_type,
                payload_json=payload_json,
                prev_hash=prev_hash or GENESIS_PREV_HASH,
                entry_hash=compute_entry_hash(
                    prev_hash or GENESIS_PREV_HASH, payload_json, event_type, created_at
                ),
                created_at=created_at,
            )
            session.add(entry)
            session.commit()
            session.refresh(entry)
            return entry

    def get_audit_trail(self, run_id: str) -> list[AuditLogEntry]:
        """Return all audit entries for ``run_id`` in append order."""
        with self._session_factory() as session:
            return list(
                session.execute(
                    select(AuditLogEntry)
                    .where(AuditLogEntry.run_id == run_id)
                    .order_by(AuditLogEntry.id)
                ).scalars()
            )

    def verify_chain(self, run_id: str) -> bool:
        """Recompute the whole hash chain for ``run_id``.

        Returns ``True`` only if every entry's stored hash matches its
        recomputed hash and links to its predecessor. An empty trail is
        vacuously intact. Detects any altered payload, event type, timestamp,
        link or hash (Batch 2 Task A requirement, unit-tested by tampering a
        row directly).
        """
        expected_prev = GENESIS_PREV_HASH
        for entry in self.get_audit_trail(run_id):
            recomputed = compute_entry_hash(
                expected_prev, entry.payload_json, entry.event_type, entry.created_at
            )
            if entry.prev_hash != expected_prev or entry.entry_hash != recomputed:
                return False
            expected_prev = entry.entry_hash
        return True

    # ------------------------------------------------------------ deliveries

    def is_delivery_processed(self, delivery_id: str) -> bool:
        """True if this webhook delivery was already accepted (replay guard)."""
        with self._session_factory() as session:
            return session.get(ProcessedDelivery, delivery_id) is not None

    def mark_delivery_processed(self, delivery_id: str, run_id: str) -> None:
        """Record a delivery as processed. Idempotent: re-marking is a no-op."""
        with self._session_factory() as session:
            existing = session.get(ProcessedDelivery, delivery_id)
            if existing is not None:
                return
            session.add(
                ProcessedDelivery(delivery_id=delivery_id, run_id=run_id, received_at=utcnow())
            )
            session.commit()
