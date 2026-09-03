"""ESLint (Node lint/SAST-lite) parser — ``eslint -f json`` format (Batch 6).

Fixture shape (eslint's JSON formatter, an ARRAY):
    [{"filePath": "/repo/src/app.js", "messages": [
        {"ruleId": "no-eval", "severity": 2, "line": 7, "column": 3,
         "message": "eval can be harmful", "nodeType": "CallExpression"}],
      "errorCount": 1, "warningCount": 0}]

NOTE (flagged in NOTES.md): the Node.js planner stage is `lint.eslint`
(quality gate). ESLint severities are lint qualities (2=error, 1=warning),
not security metrics — the parser exists so findings from lint-type stages
normalize consistently; severity mapping is error→HIGH, warning→LOW
(documented decision in severity_mapping.py). eslint emits TEXT on stdout by
default — the compiled command must add `-f json` for parsing to work
(Flagged: the nodejs template's eslint command currently has no `-f json` /
output file; wiring follows NOTES.md).
"""

from __future__ import annotations

from ci_agent.core.models.common import Severity
from ci_agent.security.models import NormalizedFinding, ParseOutcome
from ci_agent.security.parsers.base import FindingParser
from ci_agent.security.severity_mapping import ESLINT_SEVERITY_MAP

_ESLINT_NUMERIC: dict[int, str] = {1: "warning", 2: "error"}


class EslintParser(FindingParser):
    tool_name = "eslint"

    def parse_with_status(self, raw_output: str) -> ParseOutcome:
        payload, warnings = self._load_json(raw_output)
        if payload is None:
            return ParseOutcome(findings=[], warnings=warnings)
        if not isinstance(payload, list):
            return self._warning("eslint output is not a result array")
        findings: list[NormalizedFinding] = []
        for file_result in payload:
            if not isinstance(file_result, dict):
                warnings.append("eslint result entry is not an object — skipped")
                continue
            file_path = file_result.get("filePath")
            file_name = file_path.rsplit("/", 1)[-1] if isinstance(file_path, str) else None
            for message in file_result.get("messages", []) or []:
                if not isinstance(message, dict):
                    warnings.append("eslint message is not an object — skipped")
                    continue
                native = message.get("severity")
                if isinstance(native, int):
                    severity_word = _ESLINT_NUMERIC.get(native)
                elif isinstance(native, str):
                    severity_word = native
                else:
                    severity_word = None
                if severity_word is None or severity_word not in ESLINT_SEVERITY_MAP:
                    warnings.append(f"eslint message severity {native!r} unmapped — skipped")
                    continue
                line = message.get("line")
                findings.append(
                    NormalizedFinding(
                        severity=ESLINT_SEVERITY_MAP[severity_word],
                        scanner=self.tool_name,
                        rule_id=str(message.get("ruleId", "unknown")),
                        component=file_name,
                        description=str(message.get("message", "")),
                        location=(
                            f"{file_name}:{line}"
                            if file_name is not None and isinstance(line, int)
                            else None
                        ),
                    )
                )
        if findings and all(f.severity is Severity.LOW for f in findings):
            # eslint warnings alone are lint noise; recorded, but expected to
            # sit well below security thresholds (documented, not a default).
            pass
        return ParseOutcome(findings=findings, warnings=warnings)


__all__ = ["EslintParser"]
