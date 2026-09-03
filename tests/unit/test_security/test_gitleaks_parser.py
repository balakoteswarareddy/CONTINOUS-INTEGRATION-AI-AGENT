"""Batch 6 Task B: gitleaks parser + the NON-NEGOTIABLE redaction invariant."""

from __future__ import annotations

from pathlib import Path

from ci_agent.core.models.common import Severity
from ci_agent.security.parsers.gitleaks_parser import GitleaksParser

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "security_tool_outputs"
SECRET = "AKIAIOSFODNN7EXAMPLE-REDACTED-TEST-VALUE"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_clean_scan_is_clean() -> None:
    outcome = GitleaksParser().parse_with_status(_fixture("gitleaks_clean.json"))
    assert outcome.findings == []
    assert outcome.is_clean is True


def test_secret_finding_maps_to_critical_with_location() -> None:
    outcome = GitleaksParser().parse_with_status(_fixture("gitleaks_with_secret.json"))
    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.severity is Severity.CRITICAL  # incident, not lint noise
    assert finding.rule_id == "aws-access-key-id"
    assert finding.component == "deploy/config.py"
    assert finding.location == "deploy/config.py:12"
    assert finding.description == "AWS Access Key"


def test_secret_value_never_appears_in_parsed_finding() -> None:
    """Redaction invariant at the parser boundary: no Secret/Match field."""
    outcome = GitleaksParser().parse_with_status(_fixture("gitleaks_with_secret.json"))
    for finding in outcome.findings:
        dumped = str(finding.model_dump())
        assert SECRET not in dumped
        assert "Secret" not in finding.model_fields
        assert "Match" not in finding.model_fields


def test_malformed_report_flagged_not_clean() -> None:
    outcome = GitleaksParser().parse_with_status("{broken")
    assert outcome.findings == []
    assert outcome.warnings
    assert outcome.is_clean is False
