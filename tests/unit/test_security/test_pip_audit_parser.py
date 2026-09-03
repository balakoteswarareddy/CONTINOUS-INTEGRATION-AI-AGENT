"""Batch 6 Task B: pip-audit parser against real fixture shapes."""

from __future__ import annotations

from pathlib import Path

from ci_agent.core.models.common import Severity
from ci_agent.security.parsers.pip_audit_parser import PipAuditParser

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "security_tool_outputs"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_clean_scan_zero_findings() -> None:
    outcome = PipAuditParser().parse_with_status(_fixture("pip_audit_clean.json"))
    assert outcome.findings == []
    assert outcome.is_clean is True


def test_vulnerability_normalized_with_documented_default_severity() -> None:
    outcome = PipAuditParser().parse_with_status(_fixture("pip_audit_with_vuln.json"))
    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    # No cvss_score in real pip-audit output -> documented MEDIUM default.
    assert finding.severity is Severity.MEDIUM
    assert finding.rule_id == "GHSA-hx2x-85gr-9gqq"
    assert finding.component == "flask@2.0.1"
    assert "cookie" in finding.description.lower()
    assert finding.location is None  # dependency vulns have no file location
    assert finding.scanner == "pip-audit"


def test_enriched_cvss_score_drives_severity() -> None:
    enriched = (
        '{"dependencies": [{"name": "flask", "version": "2.0.1", '
        '"vulns": [{"id": "CVE-X", "cvss_score": 9.8, "description": "d"}], '
        '"skips": []}]}'
    )
    outcome = PipAuditParser().parse_with_status(enriched)
    assert outcome.findings[0].severity is Severity.CRITICAL


def test_malformed_json_flagged() -> None:
    outcome = PipAuditParser().parse_with_status("nope{")
    assert outcome.findings == []
    assert outcome.warnings
