"""ReportSummarizer — AI-assisted report summarization (Batch 9, Task C).

AI role: produce a human-readable executive paragraph from the STRUCTURED
ManagementReport data. Input boundary (enforced): only structured fields —
pass/fail outcome, risk tier, stage names/durations, exception counts. NOT
raw logs, NOT source code, NOT finding descriptions that might contain
secrets. The report model is serialized and FILTERED to an allow-list of
keys before anything is classified or built into a prompt.

Classification ceiling: report metadata is "internal" at most; content
classified above that is never sent to a model.

Deterministic fallback: a template-filled plain-English paragraph built
directly from the structured fields — always available, never empty.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict

from ci_agent.ai.gateway.provider_registry import ModelGateway
from ci_agent.ai.guardrails.data_classifier import DataClassifier
from ci_agent.ai.guardrails.prompt_builder import PromptBuilder
from ci_agent.ai.guardrails.response_validator import ResponseValidator
from ci_agent.audit.audit_store import AuditStore
from ci_agent.reporting.report_models import ManagementReport

LOGGER = logging.getLogger("ci_agent.ai.report_summarizer")

FEATURE = "report_summarization"
CEILING = "internal"

# Structured-field allow-list: the ONLY ManagementReport keys that may enter
# a prompt (no free text, no descriptions).
_ALLOWED_REPORT_KEYS: frozenset[str] = frozenset(
    {
        "run_id",
        "outcome",
        "risk_tier",
        "stage_durations_ms",
        "policy_exceptions_count",
    }
)


class SummaryResult(BaseModel):
    """Executive summary (advisory only)."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str
    key_findings: list[str]
    ai_assisted: bool
    fallback_used: bool


class ReportSummarizer:
    """Classify -> prompt -> gateway -> validate -> summarize or fall back."""

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

    def summarize(self, report: ManagementReport, audit_store: AuditStore) -> SummaryResult:
        """Summarize a management report; deterministic fallback always available."""
        import json

        structured = {
            key: value
            for key, value in report.model_dump(mode="json").items()
            if key in _ALLOWED_REPORT_KEYS
        }
        classification = self._classifier.classify(json.dumps(structured, default=str))
        if self._classifier.exceeds_ceiling(classification, CEILING):
            return self._fallback(
                structured, [f"report data classified {classification!r}; not sent to a model"]
            )

        max_tokens = self._gateway.token_budget
        prompt = self._prompt_builder.build(FEATURE, structured, classification, max_tokens)
        from ci_agent.ai.models import AIRequest

        request = AIRequest(
            feature=FEATURE,
            prompt=prompt,
            context_classification=classification,
            max_tokens=max_tokens,
            temperature=self._temperature,
        )
        response = self._gateway.invoke(request, audit_store, run_id=report.run_id)
        validation = self._validator.validate(
            response,
            FEATURE,
            max_tokens=max_tokens,
            audit_store=audit_store,
            run_id=report.run_id,
        )
        if not validation.valid:
            return self._fallback(
                structured, [f"AI response rejected: {', '.join(validation.reasons)}"]
            )
        if response.fallback_used:
            return self._fallback(structured, ["AI assistance not configured"])

        summary, findings = self._parse(response.content)
        if not summary:
            return self._fallback(structured, ["AI response carried no summary"])
        # ADVISORY ONLY: this summary is management-facing prose over already
        # -governed structured data. It is never persisted as a policy
        # decision, approval, or evidence record.
        return SummaryResult(
            executive_summary=summary,
            key_findings=findings,
            ai_assisted=True,
            fallback_used=False,
        )

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _parse(content: str) -> tuple[str, list[str]]:
        lines = [line.strip() for line in content.strip().splitlines() if line.strip()]
        findings = [line.lstrip("- ").strip() for line in lines if line.startswith("-")]
        summary_lines = [line for line in lines if not line.startswith("-")]
        return ("\n".join(summary_lines), findings) if summary_lines else ("", findings)

    @staticmethod
    def _fallback(structured: dict[str, Any], warnings: list[str]) -> SummaryResult:
        for warning in warnings:
            LOGGER.info("report summarizer fallback: %s", warning)
        run_id = structured.get("run_id", "unknown")
        outcome = structured.get("outcome", "unknown")
        risk_tier = structured.get("risk_tier", "unknown")
        stages = structured.get("stage_durations_ms") or {}
        exceptions = int(structured.get("policy_exceptions_count") or 0)
        summary = (
            f"Run {run_id}: {outcome}. Risk tier: {risk_tier}. "
            f"{len(stages)} stages completed. {exceptions} policy violations."
        )
        findings = [
            f"Outcome: {outcome}.",
            f"Risk tier: {risk_tier}.",
            f"{len(stages)} stages recorded, {exceptions} policy exceptions.",
        ]
        return SummaryResult(
            executive_summary=summary,
            key_findings=findings,
            ai_assisted=False,
            fallback_used=True,
        )


__all__ = ["ReportSummarizer", "SummaryResult"]
