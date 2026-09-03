"""Trivy container/image-scan parser tests (Batch 7, Task A; Section 5.2 Stage 6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci_agent.core.models.common import Severity
from ci_agent.security.models import ParseOutcome
from ci_agent.security.parser_registry import UnknownParserError, get_parser

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "security_tool_outputs"


@pytest.fixture()
def parser() -> object:
    return get_parser("trivy")


def test_trivy_is_registered(parser: object) -> None:
    assert parser is not None  # get_parser would raise UnknownParserError


def test_unknown_trivy_tool_still_raises() -> None:
    with pytest.raises(UnknownParserError):
        get_parser("totally-unknown-scanner")


def test_clean_scan_is_clean(parser: object) -> None:
    raw = (FIXTURES / "trivy_clean.json").read_text(encoding="utf-8")
    outcome = parser.parse_with_status(raw)  # type: ignore[attr-defined]
    assert isinstance(outcome, ParseOutcome)
    assert outcome.is_clean
    assert outcome.findings == []


def test_findings_are_normalized(parser: object) -> None:
    raw = (FIXTURES / "trivy_with_vuln.json").read_text(encoding="utf-8")
    outcome = parser.parse_with_status(raw)  # type: ignore[attr-defined]
    # One finding per vulnerability across ALL Results entries.
    assert len(outcome.findings) == 3
    by_id = {f.rule_id: f for f in outcome.findings}
    cve = by_id["CVE-2023-0286"]
    assert cve.severity is Severity.HIGH
    assert cve.scanner == "trivy"
    assert cve.component == "libssl3@3.0.11-1~deb12u1"
    assert cve.location == "ci-agent/app:ci (debian 12.2)"
    # Documented non-1:1 default: Trivy UNKNOWN -> MEDIUM.
    assert by_id["CVE-2023-5363"].severity is Severity.MEDIUM
    assert by_id["CVE-2024-9999"].severity is Severity.MEDIUM


def test_unparseable_output_warns_not_clean(parser: object) -> None:
    outcome = parser.parse_with_status("<<<not json>>>")  # type: ignore[attr-defined]
    assert not outcome.is_clean
    assert outcome.findings == []
    assert outcome.warnings


def test_missing_results_key_warns_not_clean(parser: object) -> None:
    outcome = parser.parse_with_status(json.dumps({"SchemaVersion": 2}))  # type: ignore[attr-defined]
    assert not outcome.is_clean
    assert outcome.warnings
