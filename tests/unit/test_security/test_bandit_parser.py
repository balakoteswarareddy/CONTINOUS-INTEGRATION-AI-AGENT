"""Batch 6 Task B: Bandit parser against real fixture shapes."""

from __future__ import annotations

from pathlib import Path

from ci_agent.core.models.common import Severity
from ci_agent.security.parsers.bandit_parser import BanditParser

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "security_tool_outputs"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_clean_scan_zero_findings_and_is_clean() -> None:
    outcome = BanditParser().parse_with_status(_fixture("bandit_clean.json"))
    assert outcome.findings == []
    assert outcome.warnings == []
    assert outcome.is_clean is True


def test_findings_map_correctly_and_populate_fields() -> None:
    outcome = BanditParser().parse_with_status(_fixture("bandit_with_findings.json"))
    assert outcome.is_clean is False
    assert len(outcome.findings) == 2

    high = outcome.findings[0]
    assert high.severity is Severity.HIGH
    assert high.rule_id == "B605"
    assert high.component == "app/exec.py"
    assert high.location == "app/exec.py:42"
    assert "shell" in high.description
    assert high.scanner == "bandit"
    assert high.disposition == "open"

    low = outcome.findings[1]
    assert low.severity is Severity.LOW
    assert low.rule_id == "B101"
    assert low.location == "app/exec.py:87"


def test_parse_interface_returns_findings_list() -> None:
    findings = BanditParser().parse(_fixture("bandit_with_findings.json"))
    assert len(findings) == 2


def test_malformed_json_yields_warning_not_clean() -> None:
    outcome = BanditParser().parse_with_status("<<<not json at all>>>")
    assert outcome.findings == []
    assert outcome.warnings, "unparseable output must be flagged"
    assert outcome.is_clean is False


def test_empty_output_yields_warning_not_clean() -> None:
    outcome = BanditParser().parse_with_status("")
    assert outcome.findings == []
    assert outcome.warnings
    assert outcome.is_clean is False


def test_unexpected_shape_yields_warning() -> None:
    outcome = BanditParser().parse_with_status('{"unexpected": true}')
    assert outcome.findings == []
    assert outcome.warnings
