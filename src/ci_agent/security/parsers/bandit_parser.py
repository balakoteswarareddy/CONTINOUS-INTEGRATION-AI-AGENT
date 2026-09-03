"""Bandit (Python SAST) parser — Bandit JSON report format (Batch 6, Task B).

Fixture shape (bandit ``-f json``, i.e. bandit-report.json):
    {"errors": [], "generated_at": "...", "results": [
        {"issue_severity": "HIGH", "issue_confidence": "HIGH",
         "test_id": "B605", "test_name": "start_process_with_a_shell",
         "filename": "app.py", "line_number": 12, "issue_text": "...",
         "more_info": "https://bandit.readthedocs.io/..."}]}
"""

from __future__ import annotations

from ci_agent.security.models import NormalizedFinding, ParseOutcome
from ci_agent.security.parsers.base import FindingParser
from ci_agent.security.severity_mapping import map_severity


class BanditParser(FindingParser):
    tool_name = "bandit"

    def parse_with_status(self, raw_output: str) -> ParseOutcome:
        payload, warnings = self._load_json(raw_output)
        if payload is None:
            return ParseOutcome(findings=[], warnings=warnings)
        if not isinstance(payload, dict):
            return self._warning("bandit output is not a results{} document")
        results = payload.get("results")
        if not isinstance(results, list):
            # A results{} document without a results[] array is an unexpected
            # shape — flagged, NOT silently treated as a clean scan.
            return self._warning("bandit output has no results[] array")
        findings: list[NormalizedFinding] = []
        for index, issue in enumerate(payload.get("results", [])):
            if not isinstance(issue, dict):
                warnings.append(f"bandit results[{index}] is not an object — skipped")
                continue
            severity = map_severity(self.tool_name, str(issue.get("issue_severity", "")).upper())
            filename = issue.get("filename")
            line = issue.get("line_number")
            findings.append(
                NormalizedFinding(
                    severity=severity,
                    scanner=self.tool_name,
                    rule_id=str(issue.get("test_id", "unknown")),
                    component=filename if isinstance(filename, str) else None,
                    description=str(issue.get("issue_text", "")),
                    location=(
                        f"{filename}:{line}"
                        if isinstance(filename, str) and isinstance(line, int)
                        else None
                    ),
                )
            )
        return ParseOutcome(findings=findings, warnings=warnings)


__all__ = ["BanditParser"]
