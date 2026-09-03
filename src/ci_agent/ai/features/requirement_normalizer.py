"""RequirementNormalizer — AI-assisted intake normalization (Batch 9, Task C).

AI role: SUGGEST normalized values for ambiguous or partial intake answers
(e.g. inferring ``language_stack`` from a repository description). The model
cannot add required fields that are missing — Batch 2's
:class:`RequirementsResolver` / :class:`MissingRequirementsError` remains
the authoritative check, and it runs AFTER (and independently of) this
normalizer: normalization is pre-processing, never a replacement.

Classification ceiling: intake answers are "internal" at most — content
classified confidential or restricted is NEVER sent to a model (the feature
falls back deterministically).

Deterministic fallback: the raw answers unchanged, ``ai_assisted=False``,
``fallback_used=True``.
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

LOGGER = logging.getLogger("ci_agent.ai.requirement_normalizer")

FEATURE = "requirement_normalization"
CEILING = "internal"


class NormalizationResult(BaseModel):
    """Result of intake-answer normalization (advisory only)."""

    model_config = ConfigDict(extra="forbid")

    normalized: dict[str, Any]
    warnings: list[str] = []
    ai_assisted: bool
    fallback_used: bool


class RequirementNormalizer:
    """Classify -> prompt -> gateway -> validate -> normalize or fall back."""

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

    def normalize(
        self,
        raw_answers: dict[str, Any],
        intake_schema: dict[str, Any],
        audit_store: AuditStore,
    ) -> NormalizationResult:
        """Suggest normalized intake values; never a replacement for the
        authoritative RequirementsResolver that runs afterwards."""
        import json

        classification = self._classifier.classify(json.dumps(raw_answers, default=str))
        if self._classifier.exceeds_ceiling(classification, CEILING):
            # Content boundary: confidential/restricted intake answers never
            # reach a model — deterministic fallback.
            return self._fallback(
                raw_answers,
                [f"intake answers classified {classification!r}; not sent to a model"],
            )

        max_tokens = self._gateway.token_budget
        prompt = self._prompt_builder.build(
            FEATURE,
            {"intake_answers": raw_answers, "intake_schema_keys": sorted(intake_schema)},
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
        response = self._gateway.invoke(request, audit_store, run_id=None)
        validation = self._validator.validate(
            response, FEATURE, max_tokens=max_tokens, audit_store=audit_store, run_id=None
        )
        if not validation.valid:
            return self._fallback(
                raw_answers, [f"AI response rejected: {', '.join(validation.reasons)}"]
            )
        if response.fallback_used:
            # Noop/other fallback answered: advisory nothing to apply.
            return NormalizationResult(
                normalized=raw_answers,
                warnings=["AI assistance not configured; answers unchanged"],
                ai_assisted=False,
                fallback_used=True,
            )

        suggestions = self._parse_suggestions(response.content)
        applied: dict[str, Any] = {}
        warnings: list[str] = []
        for key, value in suggestions.items():
            if key in raw_answers and str(raw_answers.get(key)) != value:
                applied[key] = value
        if not applied:
            return NormalizationResult(
                normalized=raw_answers,
                warnings=["AI normalization returned no applicable suggestions"],
                ai_assisted=False,
                fallback_used=False,
            )
        # ADVISORY ONLY: these suggested values are pre-processing for the
        # authoritative RequirementsResolver — never a decision, and never
        # persisted as anything but intake answers a human submitted/reviewed.
        normalized = dict(raw_answers)
        normalized.update(applied)
        return NormalizationResult(
            normalized=normalized,
            warnings=warnings
            + [f"AI suggested normalized value for {key!r}" for key in sorted(applied)],
            ai_assisted=True,
            fallback_used=False,
        )

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _parse_suggestions(content: str) -> dict[str, str]:
        """Parse 'key: value' suggestion lines; only existing keys apply."""
        suggestions: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip().lstrip("-").strip()
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key and value:
                suggestions[key] = value
        return suggestions

    @staticmethod
    def _fallback(raw_answers: dict[str, Any], warnings: list[str]) -> NormalizationResult:
        return NormalizationResult(
            normalized=raw_answers,
            warnings=warnings,
            ai_assisted=False,
            fallback_used=True,
        )


__all__ = ["NormalizationResult", "RequirementNormalizer"]
