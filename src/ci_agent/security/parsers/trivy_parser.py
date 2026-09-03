"""Trivy (container/image scanner) parser — ``trivy image --format json``.

Fixture shape (Trivy JSON):
    {"SchemaVersion": 2, "ArtifactName": "ci-agent/app:ci",
     "Results": [{"Target": "python:3.11-slim (debian 12.2)",
                  "Class": "os-pkgs", "Type": "debian",
                  "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-...",
                                       "PkgName": "libssl3",
                                       "InstalledVersion": "3.0.11-1",
                                       "FixedVersion": "3.0.13-1",
                                       "Severity": "HIGH",
                                       "Title": "...", "PrimaryURL": "..."}]}]}

``Vulnerabilities`` may be ``null`` (a clean target) or missing; multiple
``Results`` entries (os-pkgs + language packages) each contribute findings.
Severity mapping goes through the explicit TRIVY map — including the
documented non-1:1 choice UNKNOWN -> MEDIUM (unscorable published
vulnerability, consistent with the pip-audit default).
"""

from __future__ import annotations

from ci_agent.security.models import NormalizedFinding, ParseOutcome
from ci_agent.security.parsers.base import FindingParser
from ci_agent.security.severity_mapping import map_severity


class TrivyParser(FindingParser):
    tool_name = "trivy"

    def parse_with_status(self, raw_output: str) -> ParseOutcome:
        payload, warnings = self._load_json(raw_output)
        if payload is None:
            return ParseOutcome(findings=[], warnings=warnings)
        if not isinstance(payload, dict):
            return self._warning("trivy output has no Results[] array")
        results = payload.get("Results")
        if not isinstance(results, list):
            return self._warning("trivy output has no Results[] array")

        findings: list[NormalizedFinding] = []
        for result in results:
            if not isinstance(result, dict):
                warnings.append("trivy result entry is not an object — skipped")
                continue
            target = result.get("Target")
            target_str = str(target) if isinstance(target, str) else "unknown-target"
            vulnerabilities = result.get("Vulnerabilities")
            if vulnerabilities is None:
                continue  # explicit null = clean target, not a parse problem
            if not isinstance(vulnerabilities, list):
                warnings.append(
                    f"trivy vulnerabilities for target {target_str!r} is not a list — skipped"
                )
                continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    warnings.append(f"trivy vulnerability on {target_str!r} is not an object")
                    continue
                vulnerability_id = vulnerability.get("VulnerabilityID")
                native_severity = vulnerability.get("Severity")
                if not isinstance(vulnerability_id, str) or not isinstance(native_severity, str):
                    warnings.append(
                        f"trivy vulnerability on {target_str!r} missing id/severity — skipped"
                    )
                    continue
                package = vulnerability.get("PkgName")
                installed = vulnerability.get("InstalledVersion")
                component = (
                    f"{package}@{installed}"
                    if isinstance(package, str) and isinstance(installed, str)
                    else (package if isinstance(package, str) else None)
                )
                title = vulnerability.get("Title") or vulnerability.get("PrimaryURL") or ""
                findings.append(
                    NormalizedFinding(
                        severity=map_severity(self.tool_name, native_severity),
                        scanner=self.tool_name,
                        rule_id=vulnerability_id,
                        component=component,
                        description=str(title),
                        location=target_str,
                    )
                )
        return ParseOutcome(findings=findings, warnings=warnings)


__all__ = ["TrivyParser"]
