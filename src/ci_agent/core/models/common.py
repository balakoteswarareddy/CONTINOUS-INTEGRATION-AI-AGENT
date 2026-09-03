"""Shared enums and primitive validators for the canonical data models.

These types are referenced across PipelineSpec, PolicySpec, ExecutionPlan and
EvidenceModel (CI-Agent Production Architecture Report, Section 4.1 and
Section 6). Every enum subclasses ``str`` so instances serialize cleanly to
JSON and compare equal to their literal values.
"""

from __future__ import annotations

import re
from enum import Enum


class EventType(str, Enum):
    """Source-control events that can trigger a pipeline run (Report Section 4.1, bullet 1)."""

    PULL_REQUEST = "pull_request"
    PUSH = "push"
    MERGE = "merge"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class StageStatus(str, Enum):
    """Lifecycle status of a pipeline stage during execution (Report Section 4.1, bullet 3)."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    """Finding severity levels reported by scanners (Report Section 6 — Security family)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ApprovalStatus(str, Enum):
    """Status of a human approval record (Report Section 6 — Approval family)."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class RiskTier(str, Enum):
    """Project risk tier assigned at intake; drives approvals (Report Sections 6 and 14)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    REGULATED = "regulated"


class PolicyDecision(str, Enum):
    """Deterministic outcome of a policy evaluation (Report Section 6 — policy families)."""

    PASS = "pass"
    FAIL = "fail"
    WAIVED = "waived"


SEMVER_PATTERN: str = (
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SEMVER_RE: re.Pattern[str] = re.compile(SEMVER_PATTERN)


def validate_semver(value: str) -> str:
    """Return ``value`` if it is a valid semantic version string, else raise ``ValueError``.

    Used by every field that the report describes as a "semantic version string"
    (e.g. ``PipelineSpec.policy_version``, ``PolicySpec.policy_version``).
    """
    if not isinstance(value, str) or not _SEMVER_RE.match(value):
        raise ValueError(f"Invalid semantic version string: {value!r} (expected e.g. '1.0.0')")
    return value
