"""Exception service (Batch 7, Task D; Sections 6, 7.3, 18).

The SINGLE governed creation/management path for security exceptions:

* :meth:`ExceptionService.grant_exception` — the only code in the system
  that may write an exception row (Section 6 critical principle; Section
  7.3 "Policy bypass" threat control — inspection-tested that no other
  module creates exceptions);
* :meth:`ExceptionService.get_active_exceptions` — read side used by the
  PDP; expiry is derived from the clock (no manual expiry job required for
  correctness — :meth:`expire_due_exceptions` is hygiene only);
* :meth:`ExceptionService.revoke_exception` — explicit revocation.

Every state change is audited. The audit payload carries scope/reason/actor
and the exception id — never policy-bypass leverage beyond that.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.models import ExceptionRecord as ExceptionRecordRow
from ci_agent.exceptions.models import WILDCARD_RULE_ID, ExceptionRecord, ExceptionStatus, utcnow


class ExceptionService:
    """Grant / check / revoke governed exceptions (audit-written)."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        audit_store: AuditStore,
    ) -> None:
        self._session_factory = session_factory
        self._audit_store = audit_store

    # ------------------------------------------------------------------ grant

    def grant_exception(
        self,
        *,
        project_id: str,
        policy_family: str,
        reason: str,
        granted_by: str,
        expires_at: datetime,
        rule_id: str | None = None,
    ) -> ExceptionRecord:
        """Persist one time-boxed exception; audit the grant.

        ``expires_at`` is REQUIRED and must lie in the future at grant time —
        a permanent or already-expired waiver is rejected (Section 18).
        """
        if expires_at is None:
            raise ValueError("expires_at is REQUIRED — exceptions always have expiry times")
        now = utcnow()
        record = ExceptionRecord(
            id=f"exc-{uuid.uuid4()}",
            project_id=project_id,
            policy_family=policy_family,
            rule_id=rule_id if rule_id not in ("", None) else None,
            reason=reason,
            granted_by=granted_by,
            granted_at=now,
            expires_at=expires_at,  # pydantic validates ordering vs granted_at
        )
        if record.expires_at <= now:
            raise ValueError("expires_at must be in the future at grant time")
        with self._session_factory() as session:
            session.add(
                ExceptionRecordRow(
                    id=record.id,
                    project_id=record.project_id,
                    policy_family=record.policy_family,
                    rule_id=record.rule_id,
                    reason=record.reason,
                    granted_by=record.granted_by,
                    granted_at=record.granted_at,
                    expires_at=record.expires_at,
                    status=ExceptionStatus.ACTIVE.value,
                )
            )
            session.commit()
        self._audit_store.append_event(
            "exception",
            "exception_granted",
            {
                "exception_id": record.id,
                "project_id": record.project_id,
                "policy_family": record.policy_family,
                "rule_id": record.rule_id or WILDCARD_RULE_ID,
                "granted_by": record.granted_by,
                "expires_at": record.expires_at.isoformat(),
            },
        )
        return record

    # ------------------------------------------------------------------ reads

    def get_record(self, exception_id: str) -> ExceptionRecord:
        """Load one exception record (raises LookupError when unknown)."""
        with self._session_factory() as session:
            row = session.get(ExceptionRecordRow, exception_id)
            if row is None:
                raise LookupError(f"exception {exception_id!r} does not exist")
            session.expunge(row)
        return self._to_model(row)

    def get_active_exceptions(
        self, project_id: str, policy_family: str | None = None
    ) -> list[ExceptionRecord]:
        """All non-revoked, non-expired exceptions for a project (and family).

        Expiry is enforced by comparison against the clock HERE — an
        exception past its expiry is inactive automatically, with no manual
        intervention (Section 18).
        """
        now = utcnow()
        active: list[ExceptionRecord] = []
        for row in self._rows(project_id=project_id, policy_family=policy_family):
            model = self._to_model(row)
            if model.is_active(now):
                active.append(model)
        return active

    def find_covering_exception(
        self, project_id: str, policy_family: str, rule_id: str | None
    ) -> ExceptionRecord | None:
        """The active exception covering (family, rule), or None."""
        for model in self.get_active_exceptions(project_id, policy_family):
            if model.covers(policy_family, rule_id):
                return model
        return None

    # ----------------------------------------------------------------- revoke

    def revoke_exception(self, exception_id: str, *, revoked_by: str) -> ExceptionRecord:
        """Revoke one exception; audit the revocation (fail-loud on unknown)."""
        with self._session_factory() as session:
            row = session.get(ExceptionRecordRow, exception_id)
            if row is None:
                raise LookupError(f"exception {exception_id!r} does not exist")
            row.status = ExceptionStatus.REVOKED.value
            row.revoked_by = revoked_by
            row.revoked_at = utcnow()
            session.commit()
            session.expunge(row)
        self._audit_store.append_event(
            "exception",
            "exception_revoked",
            {"exception_id": exception_id, "revoked_by": revoked_by},
        )
        return self._to_model(row)

    def expire_due_exceptions(self, project_id: str | None = None) -> int:
        """Flip stored status to ``expired`` for past-expiry rows (hygiene).

        Correctness NEVER depends on this running: reads derive expiry from
        the clock. Returns the number of rows flipped (documented; a periodic
        caller may be wired in a later batch).
        """
        now = utcnow()
        flipped = 0
        with self._session_factory() as session:
            rows = (
                session.execute(
                    select(ExceptionRecordRow).where(
                        ExceptionRecordRow.status == ExceptionStatus.ACTIVE.value,
                        ExceptionRecordRow.expires_at <= now,
                        *(
                            []
                            if project_id is None
                            else [ExceptionRecordRow.project_id == project_id]
                        ),
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                row.status = ExceptionStatus.EXPIRED.value
                flipped += 1
            session.commit()
        if flipped:
            self._audit_store.append_event("exception", "exceptions_expired", {"count": flipped})
        return flipped

    # --------------------------------------------------------------- internals

    def _rows(
        self, project_id: str | None = None, policy_family: str | None = None
    ) -> list[ExceptionRecordRow]:
        with self._session_factory() as session:
            stmt = select(ExceptionRecordRow)
            if project_id is not None:
                stmt = stmt.where(ExceptionRecordRow.project_id == project_id)
            if policy_family is not None:
                stmt = stmt.where(ExceptionRecordRow.policy_family == policy_family)
            rows = list(session.execute(stmt).scalars().all())
            for row in rows:
                session.expunge(row)
        return rows

    @staticmethod
    def _to_model(row: ExceptionRecordRow) -> ExceptionRecord:
        return ExceptionRecord(
            id=row.id,
            project_id=row.project_id,
            policy_family=row.policy_family,
            rule_id=row.rule_id,
            reason=row.reason,
            granted_by=row.granted_by,
            granted_at=row.granted_at,
            expires_at=row.expires_at,
            status=ExceptionStatus(row.status),
            revoked_by=row.revoked_by,
            revoked_at=row.revoked_at,
        )


__all__ = ["ExceptionService"]
