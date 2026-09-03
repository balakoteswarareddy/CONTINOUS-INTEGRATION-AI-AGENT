"""Security Evidence Service (Batch 6, Task C; Report Sections 4.2, 5.1, 9).

Orchestrates: raw tool output -> registry parser -> normalized findings ->
persisted :class:`FindingRecord` rows + per-stage summary on
``StageExecutionRecord.findings_ref`` + a summary-only ``findings_collected``
audit event.

Fail-closed rules baked in here:
* an unregistered tool raises :class:`UnknownParserError` (loud, never skip);
* malformed tool output persists ZERO findings but flags a ParserWarning on
  the stage summary — downstream (PDP facts, gates) treats a warning as a
  security violation, never as a clean scan;
* raw secret VALUES are never stored or logged (gitleaks invariant, tested).
"""

from __future__ import annotations

import json
import logging
from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.common import Severity
from ci_agent.db.models import FindingRecord, StageExecutionRecord
from ci_agent.security.models import ParseOutcome
from ci_agent.security.parser_registry import get_parser

LOGGER = logging.getLogger("ci_agent.security")

# Stage ids whose tool output is security-relevant (parsed + persisted).
SCAN_STAGE_TOOLS: dict[str, str] = {
    "sast": "bandit",  # python stack; nodejs sast stage uses semgrep
    "secret_scan": "gitleaks",
    "dependency_scan": "pip-audit",  # nodejs dependency stage uses npm-audit
}


class SecurityEvidenceService:
    """Parse, persist, and summarize security findings for runs."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        audit_store: AuditStore,
    ) -> None:
        self._session_factory = session_factory
        self._audit_store = audit_store

    def collect_findings(
        self,
        run_id: str,
        stage_id: str,
        tool_name: str,
        raw_output: str,
    ) -> list[FindingRecord]:
        """Parse ``raw_output`` for one stage; persist findings + summary.

        Returns the persisted rows (empty list when the scan was clean OR
        produced a parser warning — check the stage summary to distinguish).
        The audit event carries ONLY counts, never finding payloads (a leaked
        secret value must not enter the audit trail).
        """
        parser = get_parser(tool_name)  # UnknownParserError -> loud failure
        outcome: ParseOutcome = parser.parse_with_status(raw_output)

        records: list[FindingRecord] = []
        with self._session_factory() as session:
            for finding in outcome.findings:
                record = FindingRecord(
                    run_id=run_id,
                    stage_id=stage_id,
                    scanner=finding.scanner,
                    rule_id=finding.rule_id,
                    severity=finding.severity.value,
                    component=finding.component,
                    description=finding.description,
                    location=finding.location,
                    disposition=finding.disposition,
                )
                session.add(record)
                records.append(record)
            summary = self._summary_document(outcome)
            self._write_stage_summary(session, run_id, stage_id, summary)
            session.commit()

        # Summary-only audit event: counts by severity + warning flags.
        # NEVER finding payloads (could contain secret values / source text).
        self._audit_store.append_event(
            run_id,
            "findings_collected",
            {
                "stage_id": stage_id,
                "tool_name": tool_name,
                "count": len(outcome.findings),
                "by_severity": dict(
                    sorted(
                        (sev.value, n)
                        for sev, n in Counter(f.severity for f in outcome.findings).items()
                    )
                ),
                "parser_warnings": list(outcome.warnings),
            },
        )
        for warning in outcome.warnings:
            LOGGER.warning(
                "findings parser warning for run=%s stage=%s tool=%s: %s",
                run_id,
                stage_id,
                tool_name,
                warning,
            )
        return records

    def get_findings_for_run(self, run_id: str) -> list[FindingRecord]:
        """All persisted findings for a run, oldest first."""
        return list(
            self._session_factory()
            .execute(
                select(FindingRecord)
                .where(FindingRecord.run_id == run_id)
                .order_by(FindingRecord.id)
            )
            .scalars()
            .all()
        )

    def get_findings_summary(self, run_id: str) -> dict[Severity, int]:
        """Count of persisted findings per governed severity (PDP input)."""
        counter: Counter[Severity] = Counter()
        for record in self.get_findings_for_run(run_id):
            counter[Severity(record.severity)] += 1
        return dict(counter)

    def has_parser_warnings(self, run_id: str) -> bool:
        """True when any stage of the run flagged unparseable tool output.

        Source of truth: the ``findings_collected`` AUDIT events (durable
        regardless of whether the stage row exists yet — reconciliation can
        observe a stage terminal before its row exists). Stage summaries are
        a secondary mirror.
        """
        return bool(self.parser_warnings(run_id))

    def parser_warnings(self, run_id: str) -> list[dict[str, object]]:
        """Per-stage parser warnings for a run (PDP fail-closed evidence)."""
        flagged: list[dict[str, object]] = []
        seen_stages: set[str] = set()
        for entry in self._audit_store.get_audit_trail(run_id):
            if entry.event_type != "findings_collected":
                continue
            payload = json.loads(entry.payload_json)
            warnings = payload.get("parser_warnings") or []
            stage_id = str(payload.get("stage_id", ""))
            if warnings and stage_id not in seen_stages:
                seen_stages.add(stage_id)
                flagged.append({"stage_id": stage_id, "warnings": warnings})
        return flagged

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _summary_document(outcome: ParseOutcome) -> str:
        by_severity: Counter[str] = Counter(finding.severity.value for finding in outcome.findings)
        return json.dumps(
            {
                "count": len(outcome.findings),
                "by_severity": dict(sorted(by_severity.items())),
                "parser_warnings": list(outcome.warnings),
            },
            sort_keys=True,
        )

    def _write_stage_summary(
        self, session: Session, run_id: str, stage_id: str, summary_json: str
    ) -> None:
        record = session.execute(
            select(StageExecutionRecord).where(
                StageExecutionRecord.run_id == run_id,
                StageExecutionRecord.stage_id == stage_id,
            )
        ).scalar_one_or_none()
        if record is None:
            # Stage not yet observed via webhook: findings still persist (the
            # summary attaches when the observer creates the stage row).
            return
        record.findings_ref = summary_json


__all__ = ["SCAN_STAGE_TOOLS", "SecurityEvidenceService"]
