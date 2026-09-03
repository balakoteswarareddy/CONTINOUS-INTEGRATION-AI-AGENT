"""PipelineExplainer — AI-assisted pipeline explanation (Batch 9, Task C).

AI role: produce a human-readable explanation of what a pipeline will do,
stage by stage ("what will this run do?"). Input boundary: stage names, tool
names and command template ids from the :class:`ExecutionPlan` — no source
code, no secret references, no credential values. Pipeline structure
metadata is "public" classification (confirmed by the DataClassifier on the
actual payload).

Deterministic fallback: a structured list of stage + tool lines — always
readable, never empty.
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
from ci_agent.core.models.execution_plan import ExecutionPlan

LOGGER = logging.getLogger("ci_agent.ai.pipeline_explainer")

FEATURE = "pipeline_explanation"


class ExplanationResult(BaseModel):
    """Design-time pipeline explanation (advisory only)."""

    model_config = ConfigDict(extra="forbid")

    explanation: str
    stage_summaries: list[str]
    ai_assisted: bool
    fallback_used: bool


class PipelineExplainer:
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

    def explain(self, plan: ExecutionPlan, audit_store: AuditStore) -> ExplanationResult:
        """Explain what the pipeline will do; deterministic fallback always available."""
        import json

        stages = [
            {
                "stage_id": step.stage_id,
                "tool_name": step.tool_name,
                "command_template_id": step.command_template_id,
                "depends_on": list(step.depends_on),
            }
            for step in plan.resolved_steps
        ]
        data: dict[str, Any] = {"stages": stages}
        classification = self._classifier.classify(json.dumps(data, default=str))
        if classification in ("confidential", "restricted"):
            return self._fallback(
                stages, [f"pipeline metadata classified {classification!r}; not sent to a model"]
            )

        max_tokens = self._gateway.token_budget
        prompt = self._prompt_builder.build(FEATURE, data, classification, max_tokens)
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
                stages, [f"AI response rejected: {', '.join(validation.reasons)}"]
            )
        if response.fallback_used:
            return self._fallback(stages, ["AI assistance not configured"])

        explanation, summaries = self._parse(response.content)
        if not explanation:
            return self._fallback(stages, ["AI response carried no explanation"])
        # ADVISORY ONLY: this explanation is human-facing prose about pipeline
        # structure. It is never persisted as a policy decision, approval,
        # or evidence record, and never influences execution.
        return ExplanationResult(
            explanation=explanation,
            stage_summaries=summaries,
            ai_assisted=True,
            fallback_used=False,
        )

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _parse(content: str) -> tuple[str, list[str]]:
        lines = [line.strip() for line in content.strip().splitlines() if line.strip()]
        summaries = [line.lstrip("- ").strip() for line in lines if line.startswith("-")]
        explanation_lines = [line for line in lines if not line.startswith("-")]
        return ("\n".join(explanation_lines), summaries) if explanation_lines else ("", summaries)

    @staticmethod
    def _fallback(stages: list[dict[str, Any]], warnings: list[str]) -> ExplanationResult:
        for warning in warnings:
            LOGGER.info("pipeline explainer fallback: %s", warning)
        summaries = [
            f"stage {stage['stage_id']}: run {stage['tool_name']} "
            f"(template {stage['command_template_id']})"
            for stage in stages
        ]
        explanation = (
            f"The pipeline will run {len(stages)} stage(s) in dependency order:\n"
            + "\n".join(f"- {line}" for line in summaries)
        )
        return ExplanationResult(
            explanation=explanation,
            stage_summaries=summaries,
            ai_assisted=False,
            fallback_used=True,
        )


__all__ = ["ExplanationResult", "PipelineExplainer"]
