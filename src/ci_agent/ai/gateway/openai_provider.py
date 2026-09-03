"""OpenAI-compatible HTTP provider (Batch 9, Task A).

httpx DIRECTLY against the chat-completions API — no ``openai`` SDK (the
vendor-neutral constraint shared with the runner adapters). Auth is the
``OPENAI_API_KEY`` environment variable: never hardcoded, never logged in
clear (only a masked ``sk-***`` indicator ever appears in logs).
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime

import httpx

from ci_agent.ai.errors import ModelProviderError
from ci_agent.ai.gateway.base import ModelProvider
from ci_agent.ai.models import AIRequest, AIResponse

LOGGER = logging.getLogger("ci_agent.ai.openai")

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT_SECONDS = 30.0
AVAILABILITY_TIMEOUT_SECONDS = 2.0
OPENAI_API_KEY_VARIABLE = "OPENAI_API_KEY"
OPENAI_MODEL_VARIABLE = "OPENAI_MODEL"


def _masked_key(api_key: str) -> str:
    """Masked log indicator — the key itself never reaches a log line."""
    return f"{api_key[:3]}***" if api_key.startswith("sk-") else "***"


class OpenAIProvider(ModelProvider):
    """Speaks the OpenAI chat-completions HTTP contract."""

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
        self._api_key = (api_key or os.environ.get(OPENAI_API_KEY_VARIABLE) or "").strip()
        self._base_url = base_url.rstrip("/")
        self._model = model or os.environ.get(OPENAI_MODEL_VARIABLE) or DEFAULT_MODEL
        self._timeout_seconds = timeout_seconds
        self._availability_timeout_seconds = availability_timeout_seconds
        self._client = http_client or httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}" if self._api_key else "",
                "Content-Type": "application/json",
            },
            timeout=timeout_seconds,
        )

    @property
    def provider_name(self) -> str:
        return "openai"

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
                f"{OPENAI_API_KEY_VARIABLE} is not configured "
                f"(key indicator: {_masked_key(self._api_key) or 'absent'})",
                provider=self.provider_name,
            )
        payload: dict[str, object] = {
            "model": self._model,
            "messages": [{"role": "user", "content": request.prompt}],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        started = time.monotonic()
        try:
            response = self._client.post("/chat/completions", json=payload)
        except httpx.TimeoutException as exc:
            raise ModelProviderError(
                f"chat/completions timed out after {self._timeout_seconds}s",
                provider=self.provider_name,
            ) from exc
        except httpx.HTTPError as exc:
            raise ModelProviderError(
                f"chat/completions transport error: {type(exc).__name__}",
                provider=self.provider_name,
            ) from exc
        if response.status_code >= 400:
            LOGGER.warning(
                "openai request failed: http_status=%s api_key=%s",
                response.status_code,
                _masked_key(self._api_key),
            )
            raise ModelProviderError(
                f"chat/completions returned HTTP {response.status_code}",
                provider=self.provider_name,
                status_code=response.status_code,
            )
        try:
            data = response.json()
            content = str(data["choices"][0]["message"]["content"])
            usage = data.get("usage") or {}
            tokens_used = usage.get("total_tokens")
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelProviderError(
                f"chat/completions response was malformed: {type(exc).__name__}",
                provider=self.provider_name,
            ) from exc
        return AIResponse(
            request_id=request.request_id,
            provider=self.provider_name,
            content=content,
            tokens_used=int(tokens_used) if tokens_used is not None else None,
            latency_ms=int((time.monotonic() - started) * 1000),
            fallback_used=False,
            created_at=datetime.now(tz=UTC),
        )


__all__ = ["OpenAIProvider"]
