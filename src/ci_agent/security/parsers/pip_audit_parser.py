"""pip-audit (Python SCA) parser — pip-audit JSON format (Batch 6, Task B).

Fixture shape (``pip-audit -f json``):
    {"dependencies": [
        {"name": "flask", "version": "2.0.1",
         "vulns": [{"id": "GHSA-hx2x-85gr-9gqq", "fix_versions": ["2.3.2"],
                    "aliases": ["CVE-2023-30861"], "description": "..."}],
         "skips": []}],
     "fixes": []}

Real pip-audit vulns carry NO severity/CVSS score; the documented default
maps every vuln to MEDIUM unless an enriched pipeline attaches a
``cvss_score`` key (see severity_mapping.pip_audit_severity_from_cvss).
"""

from __future__ import annotations

from ci_agent.security.models import NormalizedFinding, ParseOutcome
from ci_agent.security.parsers.base import FindingParser
from ci_agent.security.severity_mapping import pip_audit_severity_from_cvss


class PipAuditParser(FindingParser):
    tool_name = "pip-audit"

    def parse_with_status(self, raw_output: str) -> ParseOutcome:
        payload, warnings = self._load_json(raw_output)
        if payload is None:
            return ParseOutcome(findings=[], warnings=warnings)
        if not isinstance(payload, dict):
            return self._warning("pip-audit output is not a dependencies{} document")
        dependencies = payload.get("dependencies")
        if not isinstance(dependencies, list):
            return self._warning("pip-audit output has no dependencies[] array")
        findings: list[NormalizedFinding] = []
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                warnings.append("pip-audit dependency entry is not an object — skipped")
                continue
            name = dependency.get("name")
            version = dependency.get("version")
            component = (
                f"{name}@{version}"
                if isinstance(name, str) and isinstance(version, str)
                else (name if isinstance(name, str) else None)
            )
            for vuln in dependency.get("vulns", []) or []:
                if not isinstance(vuln, dict):
                    warnings.append(f"pip-audit vuln on {component!r} is not an object — skipped")
                    continue
                raw_score: float | None = None
                score_value = vuln.get("cvss_score")
                if isinstance(score_value, (int, float)):
                    raw_score = float(score_value)
                findings.append(
                    NormalizedFinding(
                        severity=pip_audit_severity_from_cvss(raw_score),
                        scanner=self.tool_name,
                        rule_id=str(vuln.get("id", "unknown")),
                        component=component,
                        description=str(vuln.get("description", "")),
                        location=None,  # dependency vulns have no file location
                    )
                )
        return ParseOutcome(findings=findings, warnings=warnings)


__all__ = ["PipAuditParser"]
