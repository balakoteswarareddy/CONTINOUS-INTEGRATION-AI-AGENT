"""Unit tests for EvidenceModel (Batch 1, Task B — Report Section 4.1, bullet 4)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ci_agent.core.models.common import ApprovalStatus, Severity
from ci_agent.core.models.evidence_model import EvidenceModel


def evidence_payload() -> dict:
    """A fully valid EvidenceModel payload."""
    return {
        "run_id": "run-2026-09-03-0001",
        "source_commit": "abc123def456",
        "pipeline_hash": "sha256:feedface",
        "tool_versions": {"python": "3.11.8", "trivy": "0.50.1"},
        "findings": [
            {
                "severity": "high",
                "scanner": "trivy",
                "rule_id": "CVE-2026-1234",
                "component": "openssl",
                "disposition": "open",
            }
        ],
        "approvals": [
            {"approver": "alice", "status": "approved", "timestamp": "2026-09-03T10:15:00+00:00"}
        ],
        "artifacts": [
            {
                "digest": "sha256:abcdef0123",
                "registry": "ghcr.io/acme",
                "sbom_ref": "sbom.spdx.json",
                "signature_ref": "artifact.sig",
            }
        ],
        "attestations": ["slsa-provenance-v1"],
        "timestamps": {
            "started_at": "2026-09-03T10:00:00+00:00",
            "completed_at": "2026-09-03T10:20:00+00:00",
        },
    }


class TestValidConstruction:
    def test_valid_payload_constructs(self) -> None:
        evidence = EvidenceModel(**evidence_payload())

        assert evidence.run_id == "run-2026-09-03-0001"
        assert evidence.source_commit == "abc123def456"
        assert evidence.pipeline_hash == "sha256:feedface"
        assert evidence.tool_versions["trivy"] == "0.50.1"
        assert evidence.findings[0].severity is Severity.HIGH
        assert evidence.approvals[0].status is ApprovalStatus.APPROVED
        assert evidence.artifacts[0].digest == "sha256:abcdef0123"
        assert evidence.attestations == ["slsa-provenance-v1"]
        assert evidence.timestamps["completed_at"] == datetime(2026, 9, 3, 10, 20, tzinfo=UTC)

    def test_empty_evidence_bundle_is_valid(self) -> None:
        payload = {
            "run_id": "run-2",
            "source_commit": "sha",
            "pipeline_hash": "sha256:x",
        }
        evidence = EvidenceModel(**payload)

        assert evidence.findings == []
        assert evidence.approvals == []
        assert evidence.artifacts == []
        assert evidence.attestations == []
        assert evidence.tool_versions == {}
        assert evidence.timestamps == {}


class TestRequiredFields:
    @pytest.mark.parametrize("field_to_remove", ["run_id", "source_commit", "pipeline_hash"])
    def test_missing_required_field_raises(self, field_to_remove: str) -> None:
        payload = evidence_payload()
        del payload[field_to_remove]

        with pytest.raises(ValidationError) as excinfo:
            EvidenceModel(**payload)
        assert field_to_remove in str(excinfo.value)

    def test_missing_nested_required_field_raises(self) -> None:
        payload = evidence_payload()
        del payload["findings"][0]["severity"]

        with pytest.raises(ValidationError) as excinfo:
            EvidenceModel(**payload)
        assert "severity" in str(excinfo.value)

    def test_invalid_severity_rejected(self) -> None:
        payload = evidence_payload()
        payload["findings"][0]["severity"] = "apocalyptic"

        with pytest.raises(ValidationError):
            EvidenceModel(**payload)

    def test_invalid_approval_status_rejected(self) -> None:
        payload = evidence_payload()
        payload["approvals"][0]["status"] = "maybe"

        with pytest.raises(ValidationError):
            EvidenceModel(**payload)


class TestTimestampOrderingValidator:
    def test_ordered_lifecycle_timestamps_pass(self) -> None:
        evidence = EvidenceModel(**evidence_payload())
        assert evidence.timestamps["started_at"] < evidence.timestamps["completed_at"]

    def test_completed_before_started_rejected(self) -> None:
        payload = evidence_payload()
        payload["timestamps"]["completed_at"] = "2026-09-03T09:00:00+00:00"

        with pytest.raises(ValidationError, match="must not precede"):
            EvidenceModel(**payload)

    def test_single_timestamp_passes(self) -> None:
        payload = evidence_payload()
        payload["timestamps"] = {"started_at": "2026-09-03T10:00:00+00:00"}

        evidence = EvidenceModel(**payload)
        assert set(evidence.timestamps) == {"started_at"}


class TestSerialization:
    def test_model_dump_json_round_trip(self) -> None:
        evidence = EvidenceModel(**evidence_payload())

        dumped = json.loads(evidence.model_dump_json())

        assert dumped["findings"][0]["severity"] == "high"
        assert dumped["approvals"][0]["status"] == "approved"
        # Pydantic v2 serializes tz-aware UTC datetimes with a trailing "Z".
        assert dumped["timestamps"]["completed_at"] == "2026-09-03T10:20:00Z"
        reparsed = EvidenceModel(**dumped)
        assert reparsed == evidence

    def test_extra_fields_rejected(self) -> None:
        payload = evidence_payload()
        payload["secret_value"] = "leak"

        with pytest.raises(ValidationError, match="secret_value"):
            EvidenceModel(**payload)
