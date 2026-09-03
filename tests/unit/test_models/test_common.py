"""Unit tests for shared enums and helpers (Batch 1, Task B — common.py)."""

from __future__ import annotations

import json

import pytest

from ci_agent.core.models.common import (
    ApprovalStatus,
    EventType,
    PolicyDecision,
    RiskTier,
    Severity,
    StageStatus,
    validate_semver,
)

EXPECTED_MEMBERS: dict[type, frozenset[str]] = {
    EventType: frozenset({"pull_request", "push", "merge", "manual", "scheduled"}),
    StageStatus: frozenset(
        {"pending", "queued", "running", "passed", "failed", "skipped", "cancelled"}
    ),
    Severity: frozenset({"critical", "high", "medium", "low", "info"}),
    ApprovalStatus: frozenset({"not_required", "pending", "approved", "rejected", "expired"}),
    RiskTier: frozenset({"low", "medium", "high", "regulated"}),
    PolicyDecision: frozenset({"pass", "fail", "waived"}),
}


@pytest.mark.parametrize("enum_type", sorted(EXPECTED_MEMBERS, key=lambda t: t.__name__))
class TestEnumDefinitions:
    def test_members_are_exactly_as_specified(self, enum_type: type) -> None:
        assert {member.value for member in enum_type} == set(EXPECTED_MEMBERS[enum_type])

    def test_members_subclass_str(self, enum_type: type) -> None:
        member = next(iter(enum_type))
        assert isinstance(member, str)
        assert member.value == member  # str-enum equality with its literal value

    def test_members_json_serialize_to_their_value(self, enum_type: type) -> None:
        member = next(iter(enum_type))
        assert json.loads(json.dumps({"value": member})) == {"value": member.value}


class TestValidateSemver:
    @pytest.mark.parametrize(
        "value",
        [
            "0.0.1",
            "1.0.0",
            "10.20.30",
            "1.0.0-rc.1",
            "2.0.0+build.5",
            "1.2.3-beta+exp.sha.5114f85",
        ],
    )
    def test_accepts_valid_semver(self, value: str) -> None:
        assert validate_semver(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "1",
            "1.0",
            "v1.0.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.0-",
            "latest",
            "1.0.0 ",
        ],
    )
    def test_rejects_invalid_semver(self, value: str) -> None:
        with pytest.raises(ValueError, match="Invalid semantic version"):
            validate_semver(value)

    def test_rejects_non_string_input(self) -> None:
        with pytest.raises(ValueError, match="Invalid semantic version"):
            validate_semver(100)  # type: ignore[arg-type]
