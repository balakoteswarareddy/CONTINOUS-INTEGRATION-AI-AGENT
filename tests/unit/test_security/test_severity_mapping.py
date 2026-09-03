"""Batch 6 Task A: severity mapping tables — explicit, no silent defaults."""

from __future__ import annotations

import pytest

from ci_agent.core.models.common import Severity
from ci_agent.security.severity_mapping import (
    BANDIT_SEVERITY_MAP,
    ESLINT_SEVERITY_MAP,
    NPM_AUDIT_SEVERITY_MAP,
    SEMGREP_SEVERITY_MAP,
    UnknownSeverityError,
    gitleaks_severity,
    map_severity,
    pip_audit_severity_from_cvss,
)


def test_bandit_map_round_trips_all_native_values() -> None:
    assert BANDIT_SEVERITY_MAP == {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    for native, governed in BANDIT_SEVERITY_MAP.items():
        assert map_severity("bandit", native) is governed


def test_npm_audit_map_covers_full_native_vocabulary() -> None:
    assert set(NPM_AUDIT_SEVERITY_MAP) == {
        "critical",
        "high",
        "moderate",
        "low",
        "info",
    }
    assert map_severity("npm-audit", "moderate") is Severity.MEDIUM
    assert map_severity("npm-audit", "critical") is Severity.CRITICAL


def test_unknown_bandit_severity_raises_not_defaults() -> None:
    with pytest.raises(UnknownSeverityError, match="unmapped native severity 'CRITICAL'"):
        map_severity("bandit", "CRITICAL")


def test_unknown_tool_raises() -> None:
    with pytest.raises(UnknownSeverityError, match="no severity map registered"):
        map_severity("trivy", "HIGH")  # trivy map is Batch 7 scope


def test_gitleaks_all_findings_are_critical() -> None:
    """Section 5.1 Stage 7: a secret is an incident — hardwired CRITICAL."""
    assert gitleaks_severity() is Severity.CRITICAL


def test_pip_audit_cvss_banding() -> None:
    assert pip_audit_severity_from_cvss(9.8) is Severity.CRITICAL
    assert pip_audit_severity_from_cvss(7.5) is Severity.HIGH
    assert pip_audit_severity_from_cvss(5.0) is Severity.MEDIUM
    assert pip_audit_severity_from_cvss(2.1) is Severity.LOW


def test_pip_audit_unknown_defaults_to_medium_deliberately() -> None:
    """Documented default (NOTES.md): unscorable published vuln -> MEDIUM."""
    assert pip_audit_severity_from_cvss(None) is Severity.MEDIUM


def test_semgrep_and_eslint_maps_present() -> None:
    assert SEMGREP_SEVERITY_MAP["ERROR"] is Severity.HIGH
    assert ESLINT_SEVERITY_MAP["error"] is Severity.HIGH
    assert ESLINT_SEVERITY_MAP["warning"] is Severity.LOW
