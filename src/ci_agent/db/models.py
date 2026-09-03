"""ORM tables for the audit store (Batch 2, Task A; Report Sections 4.2 and 9).

Three tables:
- ``run_records`` — one row per accepted pipeline run, keyed by the run ID
  issued by the Ingress / Trigger Gateway (Section 4.2).
- ``audit_log_entries`` — append-only, hash-chained audit trail (Section 9
  "Audit trail"); each entry's hash covers the previous entry's hash, giving
  tamper-evidence without an external ledger.
- ``processed_deliveries`` — delivery-ID dedupe backing the replay guard
  (Section 7.3 "State confusion / replay" control).

Datetime convention: all datetimes are stored as naive UTC ("coordinated
universal time without offset marker"). SQLite cannot round-trip timezone
offsets stably and the audit hash chain depends on byte-stable
``created_at.isoformat()`` values, so UTC-by-convention is used throughout the
DB layer (documented in NOTES.md).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ci_agent.db.base import Base

# Application-layer status vocabulary for RunRecord.status (free string column
# per Batch 2 spec; constrained here until the state machine lands).
RUN_STATUS_ACCEPTED: Final[str] = "accepted"

# Marker used as prev_hash for the first audit entry of each run.
GENESIS_PREV_HASH: Final[str] = "GENESIS"


def utcnow() -> datetime:
    """Current UTC time as a naive datetime (see module docstring)."""

    return datetime.now(UTC).replace(tzinfo=None)


class RunRecord(Base):
    """One accepted pipeline run (Report Section 4.2 — Ingress run ID issuance)."""

    __tablename__ = "run_records"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(255), index=True)
    repository: Mapped[str] = mapped_column(String(512))
    # Value drawn from ci_agent.core.models.common.EventType.
    trigger_type: Mapped[str] = mapped_column(String(32))
    source_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Free string for now; values constrained at the application layer.
    status: Mapped[str] = mapped_column(String(32), default=RUN_STATUS_ACCEPTED)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RunRecord run_id={self.run_id!r} status={self.status!r}>"


class AuditLogEntry(Base):
    """A single append-only, hash-chained audit event (Report Section 9).

    ``entry_hash = sha256(prev_hash + canonical_json(payload) + event_type +
    created_at.isoformat())``; the first entry of a run uses
    ``prev_hash = "GENESIS"``. ``verify_chain`` (audit_store) recomputes the
    chain to detect tampering.

    Note: ``run_id`` is an indexed plain column, NOT a SQL-level foreign key —
    pre-run rejections (invalid signature, disallowed repository, ...) must be
    auditable before any RunRecord exists, so they are recorded under synthetic
    ids ("rejected:<delivery_id>"). Documented in NOTES.md.
    """

    __tablename__ = "audit_log_entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLogEntry id={self.id} run_id={self.run_id!r} event_type={self.event_type!r}>"


class ProcessedDelivery(Base):
    """A webhook delivery that has already been accepted (replay protection)."""

    __tablename__ = "processed_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ProcessedDelivery delivery_id={self.delivery_id!r}>"
