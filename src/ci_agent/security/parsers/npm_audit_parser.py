"""npm-audit (Node SCA) parser — ``npm audit --json`` format (Batch 6, Task B).

Fixture shape (npm 9+):
    {"vulnerabilities": {
        "semver": {"severity": "high", "via": [{"title": "ReDoS",
                    "source": 1059, "url": "https://github.com/advisories/...",
                    "severity": "high"}], "name": "semver",
                    "range": "<5.7.2", "fixAvailable": true}},
     "metadata": {"vulnerabilities": {"critical": 0, "high": 1, ...}}}

``via`` entries may be strings (a dependency-of relationship, not a
vulnerability itself) or advisory objects — only objects produce findings,
each mapped with npm's native severity vocabulary (critical/high/moderate/
low/info). One advisory shared by several packages yields one finding per
affected package (component = "pkg@range").
"""

from __future__ import annotations

from ci_agent.security.models import NormalizedFinding, ParseOutcome
from ci_agent.security.parsers.base import FindingParser
from ci_agent.security.severity_mapping import map_severity


class NpmAuditParser(FindingParser):
    tool_name = "npm-audit"

    def parse_with_status(self, raw_output: str) -> ParseOutcome:
        payload, warnings = self._load_json(raw_output)
        if payload is None:
            return ParseOutcome(findings=[], warnings=warnings)
        if not isinstance(payload, dict):
            return self._warning("npm-audit output has no vulnerabilities{} map")
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, dict):
            return self._warning("npm-audit output has no vulnerabilities{} map")
        findings: list[NormalizedFinding] = []
        for package, entry in sorted(vulnerabilities.items()):
            if not isinstance(entry, dict):
                warnings.append(f"npm-audit entry for {package!r} is not an object — skipped")
                continue
            package_severity = entry.get("severity")
            rng = entry.get("range")
            component = f"{package}@{rng}" if isinstance(rng, str) else str(package)
            for source in entry.get("via", []) or []:
                if not isinstance(source, dict):
                    continue  # a "via": "pkg" string = transitive relation
                # Prefer the advisory's own severity; fall back to the
                # package entry's severity if the advisory omits it.
                native = source.get("severity") or package_severity
                if not isinstance(native, str):
                    warnings.append(f"npm-audit advisory on {package!r} has no severity — skipped")
                    continue
                rule_id = source.get("source")
                url = source.get("url")
                title = source.get("title", "")
                findings.append(
                    NormalizedFinding(
                        severity=map_severity(self.tool_name, str(native)),
                        scanner=self.tool_name,
                        rule_id=str(rule_id) if rule_id is not None else str(url or "unknown"),
                        component=component,
                        description=str(title),
                        location=None,
                    )
                )
        return ParseOutcome(findings=findings, warnings=warnings)


__all__ = ["NpmAuditParser"]
