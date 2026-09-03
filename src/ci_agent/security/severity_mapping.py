"""Per-tool severity vocabulary -> governed :class:`Severity` mapping (Batch 6, Task A).

Every mapping is an explicit, hardcoded table or function. Decisions that are
NOT a direct 1:1 carry a comment here AND a NOTES.md entry — no silent
defaults anywhere:

* **bandit** — 1:1 (HIGH/MEDIUM/LOW). Unknown value raises.
* **gitleaks** — gitleaks' JSON report has NO native severity field. ALL
  secret findings map to :attr:`Severity.CRITICAL` (Section 5.1 Stage 7:
  "treat discovered secrets as security incidents, not ordinary lint
  failures"). Deliberate constant, not a guess.
* **pip-audit** — pip-audit's JSON vulns carry no severity; when a CVSS score
  is present (some pipelines enrich it) it bands CVSS-style; otherwise
  ``unknown`` maps to :attr:`Severity.MEDIUM` (documented default: an
  unscorable published vulnerability is treated as worth fixing, not ignorable).
* **npm-audit** — 1:1 over npm's own vocabulary
  (critical/high/moderate/low/info).
* **semgrep** — semgrep's ``extra.severity`` is ERROR/WARNING/INFO; mapped to
  HIGH/MEDIUM/LOW (documented; semgrep has no "critical").
* **eslint** — eslint JSON messages use severity 2=error, 1=warning; mapped
  to HIGH/LOW (documented; lint errors are quality blockers, not security
  metrics).
* **trivy** (Batch 7) — 1:1 over Trivy's CVSS-derived vocabulary
  (CRITICAL/HIGH/MEDIUM/LOW). Trivy's ``UNKNOWN`` (no CVSS available)
  maps to MEDIUM — the SAME documented default as pip-audit's unscorable
  published vulnerabilities: worth tracking, never silently ignorable.
"""

from __future__ import annotations

from ci_agent.core.models.common import Severity


class UnknownSeverityError(ValueError):
    """A native severity value has no explicit mapping for this tool.

    Raised instead of silently defaulting — an unrecognized severity word may
    mean the tool changed its format, and guessing would corrupt policy input.
    """


# --- 1:1 maps (unknown values RAISE via map_severity) ------------------------

BANDIT_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

NPM_AUDIT_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# eslint JSON: messages[].severity is 2 (error) or 1 (warning). Mapping error
# -> HIGH and warning -> LOW is a documented decision: eslint severities are
# lint qualities, not CVSS scores; errors break the build, warnings do not.
ESLINT_SEVERITY_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.LOW,
}

# semgrep extra.severity: ERROR / WARNING / INFO (semgrep has no "critical").
SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Trivy image-scan severities (CRITICAL/HIGH/MEDIUM/LOW are 1:1; UNKNOWN is
# the documented MEDIUM default — see module docstring).
TRIVY_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.MEDIUM,
}


def gitleaks_severity() -> Severity:
    """EVERY gitleaks finding is CRITICAL (Section 5.1 Stage 7).

    Gitleaks' JSON report carries no severity field; a discovered secret is a
    security incident by definition, so the mapping is a deliberate constant
    rather than a guessed table.
    """
    return Severity.CRITICAL


def pip_audit_severity_from_cvss(cvss_score: float | None) -> Severity:
    """Band a CVSS v3 score; ``None``/unknown -> MEDIUM (documented default).

    pip-audit's JSON vulns do not include severity scores; when an enriched
    pipeline attaches ``cvss_score`` we band it CVSS-style. The documented
    default for unscorable published vulnerabilities is MEDIUM — worth
    tracking, never silently treated as noise.
    """
    if cvss_score is None:
        return Severity.MEDIUM
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


_TOOL_MAPS: dict[str, dict[str, Severity]] = {
    "bandit": BANDIT_SEVERITY_MAP,
    "npm-audit": NPM_AUDIT_SEVERITY_MAP,
    "eslint": ESLINT_SEVERITY_MAP,
    "semgrep": SEMGREP_SEVERITY_MAP,
    "trivy": TRIVY_SEVERITY_MAP,
}


def map_severity(tool_name: str, native_severity: str) -> Severity:
    """Map one native severity string for ``tool_name``.

    Raises :class:`UnknownSeverityError` for unmapped values, EXCEPT the two
    documented defaults (gitleaks -> CRITICAL constant; pip-audit unknown ->
    MEDIUM) which are handled by their dedicated functions above.
    """
    mapping = _TOOL_MAPS.get(tool_name)
    if mapping is None:
        raise UnknownSeverityError(
            f"no severity map registered for tool {tool_name!r}; "
            "add an explicit map in severity_mapping.py — never default silently"
        )
    try:
        return mapping[native_severity]
    except KeyError:
        raise UnknownSeverityError(
            f"unmapped native severity {native_severity!r} for tool "
            f"{tool_name!r}; known values: {sorted(mapping)}"
        ) from None


__all__ = [
    "BANDIT_SEVERITY_MAP",
    "ESLINT_SEVERITY_MAP",
    "NPM_AUDIT_SEVERITY_MAP",
    "SEMGREP_SEVERITY_MAP",
    "TRIVY_SEVERITY_MAP",
    "UnknownSeverityError",
    "gitleaks_severity",
    "map_severity",
    "pip_audit_severity_from_cvss",
]
