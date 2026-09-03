"""AI-layer exceptions (Batch 9).

All AI-layer errors live here alongside each other (same convention as
``ci_agent.adapters.errors``) — no scattered exception definitions.
"""

from __future__ import annotations


class ModelProviderError(Exception):
    """A model provider call failed (HTTP error, timeout, malformed response).

    Carried by the gateway's fallback chain: the gateway catches this and
    moves to the next provider (ultimately the NoopProvider) — it never
    propagates to control-plane callers.
    """

    def __init__(self, message: str, *, provider: str, status_code: int | None = None) -> None:
        self.provider = provider
        self.status_code = status_code
        super().__init__(f"[{provider}] {message}")


class PromptBuildError(Exception):
    """Prompt construction failed the secret-pattern defence (Batch 9, Task B).

    Raised by :class:`ci_agent.ai.guardrails.prompt_builder.PromptBuilder`
    when any data value matches a known secret format. This is a hard,
    construction-time rejection — the request is never sent to any provider.
    """


class AIGuardrailError(Exception):
    """A guardrail rejected content before it reached a model (generic)."""


__all__ = [
    "AIGuardrailError",
    "ModelProviderError",
    "PromptBuildError",
]
