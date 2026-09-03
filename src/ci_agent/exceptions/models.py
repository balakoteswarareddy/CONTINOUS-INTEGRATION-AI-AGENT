"""Governed exception/waiver records (Batch 7, Task D; Sections 6 and 18).

Section 18 is non-negotiable here: "Security exceptions are approved outside
the model and have expiration times." Therefore:

* ``expires_at`` is REQUIRED — the model itself rejects a null/missing expiry;
* the ONLY creation path is
  :meth:`ci_agent.exceptions.exception_service.ExceptionService.grant_exception`
  (admin API) — the PDP, Planner and orchestrators can never create one
  (Section 7.3 "Policy bypass"; inspection-tested);
* "expired" is derived by comparison against the clock at read time, so an
  exception dies automatically with no manual expiry job required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

WILDCARD_RULE_ID = "*"


def utcnow() -> datetime:
    """Naive UTC (matches the DB-layer datetime convention)."""
    return datetime.now(UTC).replace(tzinfo=None)


class ExceptionStatus(StrEnum):
    """Lifecycle status of a governed exception."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ExceptionRecord(BaseModel):
    """One governed waiver, scoped and time-boxed (Section 18)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    project_id: str
    # Policy family covered (e.g. security_policy / artifact_policy).
    policy_family: str
    # The specific rule waived; None or "*" covers the whole family.
    rule_id: str | None = None
    reason: str
    granted_by: str
    granted_at: datetime
    # REQUIRED (Section 18). A missing expiry fails validation — permanent
    # exceptions cannot be expressed in this model at all.
    expires_at: datetime
    status: ExceptionStatus = ExceptionStatus.ACTIVE
    revoked_by: str | None = None
    revoked_at: datetime | None = None

    @field_validator("policy_family")
    @classmethod
    def _policy_family_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy_family must not be blank")
        return value.strip()

    @model_validator(mode="after")
    def _expiry_must_follow_grant(self) -> ExceptionRecord:
        """``expires_at`` must be required-non-null AND after ``granted_at``."""
        if self.expires_at is None:  # pragma: no cover - pydantic enforces first
            raise ValueError("expires_at is REQUIRED — permanent exceptions cannot exist")
        if self.expires_at <= self.granted_at:
            raise ValueError("expires_at must be after granted_at")
        return self

    def is_active(self, now: datetime | None = None) -> bool:
        """True only when status is active AND expiry still in the future.

        Expiry is derived from the clock: an exception past its expiry is
        treated as inactive automatically — no manual job required for
        correctness (Section 18).
        """
        if self.status is not ExceptionStatus.ACTIVE:
            return False
        moment = now or utcnow()
        return self.expires_at > moment

    def covers(self, policy_family: str, rule_id: str | None) -> bool:
        """Scope match: family must match; rule wildcard covers everything."""
        if self.policy_family != policy_family:
            return False
        if self.rule_id in (None, WILDCARD_RULE_ID):
            return True
        return rule_id is not None and self.rule_id == rule_id


__all__ = ["WILDCARD_RULE_ID", "ExceptionRecord", "ExceptionStatus"]
