"""Gitleaks (secret scan) parser — gitleaks JSON report format (Batch 6, Task B).

Fixture shape (``gitleaks detect --report-format json``, an ARRAY):
    [{"Description": "AWS Access Key", "File": "config.py", "StartLine": 12,
      "RuleID": "aws-access-key-id", "Secret": "AKIA...", "Match": "AKIA...",
      "Fingerprint": "..."}]

NON-NEGOTIABLE (Batch 6 guardrail): the ``Secret`` and ``Match`` values are
NEVER copied into any field of the normalized finding, any database row, or
any audit log payload. Only RuleID / File / StartLine survive — the parser
structurally cannot leak the secret because it never reads those keys into
the output model. Tested explicitly.
"""

from __future__ import annotations

from ci_agent.security.models import NormalizedFinding, ParseOutcome
from ci_agent.security.parsers.base import FindingParser
from ci_agent.security.severity_mapping import gitleaks_severity

# Keys that hold the sensitive material — asserted absent from every emitted
# model dump (see the redaction tests).
_FORBIDDEN_KEYS: frozenset[str] = frozenset({"Secret", "Match", "secret", "match"})


class GitleaksParser(FindingParser):
    tool_name = "gitleaks"

    def parse_with_status(self, raw_output: str) -> ParseOutcome:
        payload, warnings = self._load_json(raw_output)
        if payload is None:
            return ParseOutcome(findings=[], warnings=warnings)
        if not isinstance(payload, list):
            return self._warning("gitleaks output is not a report array")
        findings: list[NormalizedFinding] = []
        for index, leak in enumerate(payload):
            if not isinstance(leak, dict):
                warnings.append(f"gitleaks report[{index}] is not an object — skipped")
                continue
            file_name = leak.get("File")
            start_line = leak.get("StartLine")
            findings.append(
                NormalizedFinding(
                    # Section 5.1 Stage 7: a discovered secret is a security
                    # incident — every gitleaks finding is CRITICAL.
                    severity=gitleaks_severity(),
                    scanner=self.tool_name,
                    rule_id=str(leak.get("RuleID", "unknown")),
                    component=file_name if isinstance(file_name, str) else None,
                    # The rule Description (e.g. "AWS Access Key") — NOT the
                    # secret value.
                    description=str(leak.get("Description", "")),
                    location=(
                        f"{file_name}:{start_line}"
                        if isinstance(file_name, str) and isinstance(start_line, int)
                        else None
                    ),
                )
            )
        # Belt-and-braces: no emitted finding may carry sensitive keys.
        for finding in findings:
            dumped = finding.model_dump()
            leaked = _FORBIDDEN_KEYS.intersection(dumped)
            assert not leaked, f"redaction invariant violated: {leaked}"
        return ParseOutcome(findings=findings, warnings=warnings)


__all__ = ["GitleaksParser"]
