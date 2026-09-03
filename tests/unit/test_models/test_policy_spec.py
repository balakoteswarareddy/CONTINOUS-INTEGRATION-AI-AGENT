"""Unit tests for PolicySpec (Batch 1, Task B — Report Section 4.1 bullet 2 + Section 6)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ci_agent.core.models.common import RiskTier, Severity
from ci_agent.core.models.policy_spec import PolicySpec


def policy_spec_payload() -> dict:
    """A fully valid PolicySpec payload with all seven policy families (Section 6)."""
    return {
        "policy_version": "1.0.0",
        "identity_policy": {
            "allowed_repositories": ["acme/payments-api"],
            "allowed_branches": ["main", "release/*"],
            "allowed_identities": ["urn:ci:identity:acme-builder"],
        },
        "tool_policy": {
            "approved_tool_versions": {"python": "3.11.8", "node": "20.11.0"},
            "approved_images": ["ghcr.io/acme/trusted-builder:1.2.3"],
            "forbidden_tools": ["curl-bash-installer"],
        },
        "security_policy": {
            "severity_thresholds": {"critical": 0, "high": 0, "medium": 5, "low": 20},
            "require_secret_scan": True,
            "require_sca": True,
        },
        "build_policy": {
            "allowed_base_images": ["python:3.11-slim"],
            "allowed_egress_domains": ["pypi.org", "files.pythonhosted.org"],
            "max_timeout_seconds": 3600,
        },
        "artifact_policy": {
            "require_sbom": True,
            "sbom_format": "spdx",
            "require_signing": True,
            "registry_allowlist": ["ghcr.io/acme"],
        },
        "approval_policy": {
            "require_human_approval_for": ["high", "regulated"],
            "approver_groups": ["security-champions"],
        },
        "ai_policy": {
            "allowed_model_providers": [],
            "allowed_data_classification": ["public"],
            "require_human_override": True,
        },
    }


class TestValidConstruction:
    def test_valid_payload_constructs(self) -> None:
        spec = PolicySpec(**policy_spec_payload())

        assert spec.policy_version == "1.0.0"
        assert spec.identity_policy.allowed_repositories == ["acme/payments-api"]
        assert spec.tool_policy.approved_tool_versions["python"] == "3.11.8"
        assert spec.security_policy.severity_thresholds == {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 5,
            Severity.LOW: 20,
        }
        assert spec.security_policy.require_secret_scan is True
        assert spec.build_policy.max_timeout_seconds == 3600
        assert spec.artifact_policy.sbom_format == "spdx"
        # Risk tiers are coerced into the RiskTier enum.
        assert spec.approval_policy.require_human_approval_for == [
            RiskTier.HIGH,
            RiskTier.REGULATED,
        ]
        assert spec.ai_policy.require_human_override is True

    def test_empty_allowlists_are_valid_deny_by_default(self) -> None:
        payload = policy_spec_payload()
        payload["identity_policy"] = {
            "allowed_repositories": [],
            "allowed_branches": [],
            "allowed_identities": [],
        }

        spec = PolicySpec(**payload)
        assert spec.identity_policy.allowed_identities == []


class TestRequiredFields:
    @pytest.mark.parametrize(
        "field_to_remove",
        [
            "policy_version",
            "identity_policy",
            "tool_policy",
            "security_policy",
            "build_policy",
            "artifact_policy",
            "approval_policy",
            "ai_policy",
        ],
    )
    def test_missing_policy_family_raises(self, field_to_remove: str) -> None:
        payload = policy_spec_payload()
        del payload[field_to_remove]

        with pytest.raises(ValidationError) as excinfo:
            PolicySpec(**payload)
        assert field_to_remove in str(excinfo.value)

    def test_missing_nested_required_field_raises(self) -> None:
        payload = policy_spec_payload()
        del payload["security_policy"]["require_sca"]

        with pytest.raises(ValidationError) as excinfo:
            PolicySpec(**payload)
        assert "require_sca" in str(excinfo.value)

    def test_partial_severity_thresholds_are_valid(self) -> None:
        """The model types thresholds as dict[Severity, int]; partial maps are allowed."""
        payload = policy_spec_payload()
        payload["security_policy"]["severity_thresholds"] = {"critical": 0}

        spec = PolicySpec(**payload)
        assert spec.security_policy.severity_thresholds == {Severity.CRITICAL: 0}


class TestValidators:
    def test_invalid_severity_key_rejected(self) -> None:
        payload = policy_spec_payload()
        payload["security_policy"]["severity_thresholds"]["blocker"] = 0

        with pytest.raises(ValidationError):
            PolicySpec(**payload)

    def test_valid_policy_version_passes(self) -> None:
        payload = policy_spec_payload()
        payload["policy_version"] = "3.4.5"
        assert PolicySpec(**payload).policy_version == "3.4.5"

    def test_invalid_policy_version_rejected(self) -> None:
        payload = policy_spec_payload()
        payload["policy_version"] = "not-a-version"

        with pytest.raises(ValidationError, match="Invalid semantic version"):
            PolicySpec(**payload)

    def test_invalid_risk_tier_rejected(self) -> None:
        payload = policy_spec_payload()
        payload["approval_policy"]["require_human_approval_for"] = ["extreme"]

        with pytest.raises(ValidationError):
            PolicySpec(**payload)

    def test_non_positive_timeout_rejected(self) -> None:
        payload = policy_spec_payload()
        payload["build_policy"]["max_timeout_seconds"] = 0

        with pytest.raises(ValidationError):
            PolicySpec(**payload)


class TestSerialization:
    def test_model_dump_json_round_trip(self) -> None:
        spec = PolicySpec(**policy_spec_payload())

        dumped = json.loads(spec.model_dump_json())

        # Enum dict keys serialize to their string values.
        assert dumped["security_policy"]["severity_thresholds"] == {
            "critical": 0,
            "high": 0,
            "medium": 5,
            "low": 20,
        }
        assert dumped["approval_policy"]["require_human_approval_for"] == ["high", "regulated"]
        reparsed = PolicySpec(**dumped)
        assert reparsed == spec

    def test_extra_fields_rejected(self) -> None:
        payload = policy_spec_payload()
        payload["extra_family"] = {}

        with pytest.raises(ValidationError, match="extra_family"):
            PolicySpec(**payload)
