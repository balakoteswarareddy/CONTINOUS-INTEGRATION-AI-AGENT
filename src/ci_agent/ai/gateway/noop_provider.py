"""NoopProvider — the no-model fallback (Batch 9, Task A; Section 12).

The provider of last resort and the DEFAULT provider. It is always
"available" (it never fails, never times out, never costs tokens) and always
answers with a deterministic, structured plain-text response explaining that
AI assistance is not configured. This is what makes "the platform remains
functional when the AI service is unavailable" (Section 18) a structural
property rather than an error-handling afterthought: with the default
``AI_PROVIDER=noop`` the entire control plane runs deterministically.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ci_agent.ai.gateway.base import ModelProvider
from ci_agent.ai.models import AIRequest, AIResponse


class NoopProvider(ModelProvider):
    """Deterministic no-model provider. It must NEVER raise."""

    @property
    def provider_name(self) -> str:
        return "noop"

    def is_available(self) -> bool:
        # Always "available": it cannot fail, time out, or cost tokens.
        return True

    def complete(self, request: AIRequest) -> AIResponse:
        content = (
            "AI assistance is not configured for this request.\n"
            f"- feature: {request.feature}\n"
            f"- data classification: {request.context_classification}\n"
            "- provider: noop (deterministic fallback; no model was called)\n"
            "To enable AI assistance, set AI_PROVIDER=openai or anthropic with "
            "the corresponding API key, and ensure the governance policy "
            "(ai_policy.yaml allowed_data_classification) admits the request's "
            "data classification.\n"
            "This response is advisory only and requires human review before "
            "any action is taken."
        )
        return AIResponse(
            request_id=request.request_id,
            provider=self.provider_name,
            content=content,
            tokens_used=None,
            latency_ms=0,
            fallback_used=True,
            created_at=datetime.now(tz=UTC),
        )


__all__ = ["NoopProvider"]
