"""Batch 6 Task B: npm-audit parser against real fixture shapes."""

from __future__ import annotations

from pathlib import Path

from ci_agent.core.models.common import Severity
from ci_agent.security.parsers.npm_audit_parser import NpmAuditParser

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "security_tool_outputs"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_clean_scan_zero_findings() -> None:
    outcome = NpmAuditParser().parse_with_status(_fixture("npm_audit_clean.json"))
    assert outcome.findings == []
    assert outcome.is_clean is True


def test_vulnerabilities_normalized_per_package() -> None:
    outcome = NpmAuditParser().parse_with_status(_fixture("npm_audit_with_vuln.json"))
    assert len(outcome.findings) == 2

    by_rule = {finding.rule_id: finding for finding in outcome.findings}
    assert set(by_rule) == {"1059", "1113"}

    semver = by_rule["1059"]
    assert semver.severity is Severity.HIGH
    assert semver.component == "semver@<5.7.2"
    assert "denial" in semver.description.lower()

    minimist = by_rule["1113"]
    assert minimist.severity is Severity.MEDIUM  # "moderate" -> MEDIUM
    assert minimist.component == "minimist@<1.2.6"


def test_via_strings_are_transitive_relations_not_findings() -> None:
    document = (
        '{"vulnerabilities": {"lodash": {"name": "lodash", "severity": "low", '
        '"via": ["semver"], "range": "<4.17.21", "fixAvailable": true}}}'
    )
    outcome = NpmAuditParser().parse_with_status(document)
    assert outcome.findings == []
    assert outcome.warnings == []


def test_malformed_json_flagged_not_clean() -> None:
    outcome = NpmAuditParser().parse_with_status("[[[")
    assert outcome.findings == []
    assert outcome.warnings
    assert outcome.is_clean is False
