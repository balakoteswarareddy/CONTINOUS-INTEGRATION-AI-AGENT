"""Anthropic HTTP provider (Batch 9, Task A).

httpx DIRECTLY against the Anthropic ``/v1/messages`` API — no ``anthropic``
SDK (vendor-neutral constraint). This implements the Anthropic messages API
shape PROPERLY, which differs from OpenAI's chat-completions shape:

- auth header is ``x-api-key`` (plus the mandatory ``anthropic-version``
  header), not ``Authorization: Bearer``;
- ``max_tokens`` is a REQUIRED top-level body field;
- the response body is a list of typed content blocks
  (``content: [{type: "text", text: ...}]``), not ``choices[0].message``;
- usage is ``{input_tokens, output_tokens}``, not ``total_tokens``.

Both providers correctly implement their own documented API contract — that
is the entire point of vendor neutrality: either one works.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from ci_agent.ai.errors import ModelProviderError
from ci_agent.ai.gateway.base import ModelProvider
from ci_agent.ai.models import AIRequest, AIResponse

LOGGER = logging.getLogger("ci_agent.ai.anthropic")

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_MODEL = "claude-3-5-haiku-latest"
DEFAULT_TIMEOUT_SECONDS = 30.0
AVAILABILITY_TIMEOUT_SECONDS = 2.0
ANTHROPIC_API_KEY_VARIABLE = "ANTHROPIC_API_KEY"
ANTHROPIC_MODEL_VARIABLE = "ANTHROPIC_MODEL"
ANTHROPIC_VERSION_HEADER = "2023-06-01"


def _masked_key(api_key: str) -> str:
    """Masked log indicator — the key itself never reaches a log line."""
    return f"{api_key[:3]}***" if api_key.startswith("sk-ant-") else "***"


class AnthropicProvider(ModelProvider):
    """Speaks the Anthropic messages HTTP contract."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        model: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        availability_timeout_seconds: float = AVAILABILITY_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = (api_key or os.environ.get(ANTHROPIC_API_KEY_VARIABLE) or "").strip()
        self._base_url = base_url.rstrip("/")
        self._model = model or os.environ.get(ANTHROPIC_MODEL_VARIABLE) or DEFAULT_MODEL
        self._timeout_seconds = timeout_seconds
        self._availability_timeout_seconds = availability_timeout_seconds
        self._client = http_client or httpx.Client(
            base_url=self._base_url,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": ANTHROPIC_VERSION_HEADER,
                "Content-Type": "application/json",
            },
            timeout=timeout_seconds,
        )

    @property
    def provider_name(self) -> str:
        return "anthropic"

    # ------------------------------------------------------------- liveness

    def is_available(self) -> bool:
        """Lightweight models-list probe; never raises."""
        if not self._api_key:
            return False
        try:
            response = self._client.get("/models", timeout=self._availability_timeout_seconds)
            return response.status_code == 200
        except Exception:  # httpx errors, timeouts, anything — never raise
            return False

    # ------------------------------------------------------------- completion

    def complete(self, request: AIRequest) -> AIResponse:
        if not self._api_key:
            raise ModelProviderError(
                f"{ANTHROPIC_API_KEY_VARIABLE} is not configured "
                f"(key indicator: {_masked_key(self._api_key) or 'absent'})",
                provider=self.provider_name,
            )
        # Anthropic messages shape: max_tokens is REQUIRED at the top level.
        payload: dict[str, object] = {
            "model": self._model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        started = time.monotonic()
        try:
            response = self._client.post("/messages", json=payload)
        except httpx.TimeoutException as exc:
            raise ModelProviderError(
                f"messages timed out after {self._timeout_seconds}s",
                provider=self.provider_name,
            ) from exc
        except httpx.HTTPError as exc:
            raise ModelProviderError(
                f"messages transport error: {type(exc).__name__}",
                provider=self.provider_name,
            ) from exc
        if response.status_code >= 400:
            LOGGER.warning(
                "anthropic request failed: http_status=%s api_key=%s",
                response.status_code,
                _masked_key(self._api_key),
            )
            raise ModelProviderError(
                f"messages returned HTTP {response.status_code}",
                provider=self.provider_name,
                status_code=response.status_code,
            )
        try:
            data: Any = response.json()
            blocks = data["content"]
            content = "".join(
                str(block.get("text", "")) for block in blocks if block.get("type") == "text"
            )
            usage = data.get("usage") or {}
            tokens_used = (usage.get("input_tokens") or 0) + (usage.get("output_tokens") or 0)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ModelProviderError(
                f"messages response was malformed: {type(exc).__name__}",
                provider=self.provider_name,
            ) from exc
        return AIResponse(
            request_id=request.request_id,
            provider=self.provider_name,
            content=content,
            tokens_used=int(tokens_used) if tokens_used else None,
            latency_ms=int((time.monotonic() - started) * 1000),
            fallback_used=False,
            created_at=datetime.now(tz=UTC),
        )


__all__ = ["AnthropicProvider"]
