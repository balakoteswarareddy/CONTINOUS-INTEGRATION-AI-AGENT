"""FailureTriage — AI-assisted failure explanation (Batch 9, Task C).

AI role: explain WHY a stage failed and suggest remediation. The output
surfaces in the developer report (Batch 5's DeveloperReport carries an
optional ``triage`` field) — it never gates, approves, or excuses anything.

Content boundaries (enforced, not suggested):

- the log snippet is pre-truncated to MAX_LOG_LINES (500) lines;
- raw source-code lines are STRIPPED (only tool output lines remain);
- secret patterns are redacted BEFORE classification/prompt-building;
- the (redacted, filtered) snippet is classified; confidential/restricted
  content is never sent to a model.

Deterministic fallback: the static per-stage remediation-hint lookup that
the Batch 5 developer report already uses (``report_models.REMEDIATION_HINTS``).
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict

from ci_agent.ai.gateway.provider_registry import ModelGateway
from ci_agent.ai.guardrails.data_classifier import DataClassifier
from ci_agent.ai.guardrails.prompt_builder import PromptBuilder
from ci_agent.ai.guardrails.response_validator import ResponseValidator
from ci_agent.ai.models import redact_secret_patterns
from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.models import FindingRecord

LOGGER = logging.getLogger("ci_agent.ai.failure_triage")

FEATURE = "failure_triage"
MAX_LOG_LINES = 500


class TriageResult(BaseModel):
    """Advisory failure explanation (never a gate outcome)."""

    model_config = ConfigDict(extra="forbid")

    probable_cause: str
    remediation_hints: list[str]
    ai_assisted: bool
    fallback_used: bool


class FailureTriage:
    """Classify -> prompt -> gateway -> validate -> explain or fall back."""

    def __init__(
        self,
        gateway: ModelGateway,
        *,
        classifier: DataClassifier | None = None,
        prompt_builder: PromptBuilder | None = None,
        validator: ResponseValidator | None = None,
        temperature: float = 0.0,
    ) -> None:
        self._gateway = gateway
        self._classifier = classifier or DataClassifier()
        self._prompt_builder = prompt_builder or PromptBuilder()
        self._validator = validator or ResponseValidator()
        self._temperature = temperature

    def triage(
        self,
        run_id: str,
        stage_id: str,
        findings: list[FindingRecord],
        logs_snippet: str,
        audit_store: AuditStore,
    ) -> TriageResult:
        """Explain a failed stage; deterministic fallback always available."""
        # Content-boundary enforcement on the snippet, in order:
        # 1. hard line cap, 2. source lines stripped, 3. secrets redacted.
        snippet = "\n".join(logs_snippet.splitlines()[:MAX_LOG_LINES])
        snippet = self._classifier.without_source_lines(snippet)
        snippet = redact_secret_patterns(snippet)

        classification = self._classifier.classify(snippet)
        if classification in ("confidential", "restricted"):
            return self._fallback(
                stage_id,
                findings,
                [f"stage log classified {classification!r}; not sent to a model"],
            )

        finding_rows = [
            {
                "scanner": finding.scanner,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
            }
            for finding in findings
        ]
        max_tokens = self._gateway.token_budget
        prompt = self._prompt_builder.build(
            FEATURE,
            {
                "run_id": run_id,
                "stage_id": stage_id,
                "findings": finding_rows,
                "log_snippet": snippet,
            },
            classification,
            max_tokens,
        )
        from ci_agent.ai.models import AIRequest

        request = AIRequest(
            feature=FEATURE,
            prompt=prompt,
            context_classification=classification,
            max_tokens=max_tokens,
            temperature=self._temperature,
        )
        response = self._gateway.invoke(request, audit_store, run_id=run_id)
        validation = self._validator.validate(
            response, FEATURE, max_tokens=max_tokens, audit_store=audit_store, run_id=run_id
        )
        if not validation.valid:
            # Policy-bypass/secret content NEVER reaches a report or API
            # response — the sanitized content is discarded, not returned.
            return self._fallback(
                stage_id, findings, [f"AI response rejected: {', '.join(validation.reasons)}"]
            )
        if response.fallback_used:
            return self._fallback(stage_id, findings, ["AI assistance not configured"])

        probable_cause, hints = self._parse(response.content)
        if not probable_cause:
            return self._fallback(stage_id, findings, ["AI response carried no explanation"])
        # ADVISORY ONLY: this explanation is developer-facing prose. It is
        # never persisted as a policy decision, approval, or evidence record;
        # remediation is performed by a human who reads it.
        return TriageResult(
            probable_cause=probable_cause,
            remediation_hints=hints,
            ai_assisted=True,
            fallback_used=False,
        )

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _parse(content: str) -> tuple[str, list[str]]:
        """Split the model output into a cause paragraph + hint lines."""
        lines = [line.strip() for line in content.strip().splitlines() if line.strip()]
        hints = [line.lstrip("- ").strip() for line in lines if line.startswith("-")]
        cause_lines = [line for line in lines if not line.startswith("-")]
        return ("\n".join(cause_lines), hints) if cause_lines else ("", hints)

    @staticmethod
    def _fallback(stage_id: str, findings: list[Any], warnings: list[str]) -> TriageResult:
        # Lazy import: report_models imports this module (DeveloperReport
        # carries the triage field), so the static-hint table is resolved at
        # call time to keep the import graph acyclic.
        from ci_agent.reporting.report_models import REMEDIATION_HINTS, UNKNOWN_STAGE_HINT

        static_hint = REMEDIATION_HINTS.get(stage_id, UNKNOWN_STAGE_HINT)
        hints = [static_hint]
        if findings:
            hints.append(
                f"{len(findings)} security finding(s) recorded for this stage; "
                "review them in the security report."
            )
        for warning in warnings:
            LOGGER.info("failure triage fallback: %s", warning)
        return TriageResult(
            probable_cause=(f"Stage {stage_id!r} failed. Deterministic triage: " + static_hint),
            remediation_hints=hints,
            ai_assisted=False,
            fallback_used=True,
        )


__all__ = ["FailureTriage", "TriageResult"]
