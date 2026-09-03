"""ModelProvider abstract interface (Batch 9, Task A; Report Section 12).

The gateway is provider-agnostic at the interface level — exactly as the
runner adapter layer is runner-agnostic. Provider implementations speak their
own HTTP dialect (OpenAI chat completions, Anthropic messages) behind this
one contract; NO vendor SDK may be added (standing constraint — an SDK would
leak vendor types into shared code).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ci_agent.ai.models import AIRequest, AIResponse


class ModelProvider(ABC):
    """One pluggable model backend.

    Contract:

    - :meth:`complete` returns an :class:`AIResponse` or raises
      :class:`ci_agent.ai.errors.ModelProviderError` — never a bare
      exception type from the HTTP layer (the gateway's fallback chain
      depends on this).
    - :meth:`is_available` NEVER raises: any failure (missing key, timeout,
      HTTP error, transport error) is reported as ``False``.
    - :attr:`provider_name` is the stable provider identifier used in
      invocation records and logs.
    """

    @abstractmethod
    def complete(self, request: AIRequest) -> AIResponse:
        """Generate a completion for the governed request."""

    @abstractmethod
    def is_available(self) -> bool:
        """Cheap liveness/config check; never raises."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Stable provider identifier (e.g. ``openai``/``anthropic``/``noop``)."""


__all__ = ["ModelProvider"]
