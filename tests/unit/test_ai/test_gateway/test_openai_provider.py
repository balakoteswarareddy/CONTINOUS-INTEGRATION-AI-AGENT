"""OpenAI provider tests (Batch 9, Task A) — respx-mocked HTTP, zero creds."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from ci_agent.ai.errors import ModelProviderError
from ci_agent.ai.gateway.openai_provider import OpenAIProvider, _masked_key
from ci_agent.ai.models import AIRequest

BASE = "https://api.openai.test/v1"


def _request() -> AIRequest:
    return AIRequest(
        feature="failure_triage",
        prompt="Explain the failure.",
        context_classification="internal",
        max_tokens=128,
        temperature=0.0,
    )


def _provider(**kwargs: object) -> OpenAIProvider:
    kwargs.setdefault("api_key", "sk-test-0123456789abcdef")
    kwargs.setdefault("base_url", BASE)
    return OpenAIProvider(**kwargs)  # type: ignore[arg-type]


class TestAuthAndHeaders:
    @respx.mock
    def test_requests_carry_bearer_authorization(self) -> None:
        route = respx.post(f"{BASE}/chat/completions").respond(
            200,
            json={
                "choices": [{"message": {"content": "hello"}}],
                "usage": {"total_tokens": 5},
            },
        )
        response = _provider().complete(_request())
        assert response.content == "hello"
        assert route.calls[0].request.headers["Authorization"] == "Bearer sk-test-0123456789abcdef"

    def test_missing_key_is_reported_unavailable_not_raised(self) -> None:
        assert OpenAIProvider(api_key="", base_url=BASE).is_available() is False

    def test_masked_key_never_exposes_the_secret(self) -> None:
        assert _masked_key("sk-supersecretvalue") == "sk-***"
        assert _masked_key("other-format") == "***"
        assert "supersecret" not in _masked_key("sk-supersecretvalue")


class TestAvailability:
    @respx.mock
    def test_available_on_models_200(self) -> None:
        respx.get(f"{BASE}/models").respond(200, json={"data": []})
        assert _provider().is_available() is True

    @respx.mock
    def test_unavailable_on_http_error(self) -> None:
        respx.get(f"{BASE}/models").respond(500, text="boom")
        assert _provider().is_available() is False

    @respx.mock
    def test_unavailable_on_transport_error_never_raises(self) -> None:
        respx.get(f"{BASE}/models").mock(side_effect=httpx.ConnectError("nope"))
        assert _provider().is_available() is False


class TestComplete:
    @respx.mock
    def test_posts_the_chat_completions_shape(self) -> None:
        route = respx.post(f"{BASE}/chat/completions").respond(
            200,
            json={
                "choices": [{"message": {"content": "analysis"}}],
                "usage": {"total_tokens": 42},
            },
        )
        response = _provider().complete(_request())
        body = json.loads(route.calls[0].request.content)
        assert body["messages"] == [{"role": "user", "content": "Explain the failure."}]
        assert body["max_tokens"] == 128
        assert body["temperature"] == 0.0
        assert body["model"]
        assert response.tokens_used == 42
        assert response.fallback_used is False
        assert response.latency_ms >= 0

    @respx.mock
    def test_http_error_raises_model_provider_error_with_status(self) -> None:
        respx.post(f"{BASE}/chat/completions").respond(429, text="rate limited")
        with pytest.raises(ModelProviderError) as excinfo:
            _provider().complete(_request())
        assert excinfo.value.status_code == 429
        assert excinfo.value.provider == "openai"

    @respx.mock
    def test_timeout_raises_model_provider_error(self) -> None:
        respx.post(f"{BASE}/chat/completions").mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(ModelProviderError, match="timed out"):
            _provider().complete(_request())

    @respx.mock
    def test_transport_error_raises_model_provider_error(self) -> None:
        respx.post(f"{BASE}/chat/completions").mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(ModelProviderError, match="transport"):
            _provider().complete(_request())

    @respx.mock
    def test_malformed_response_raises_model_provider_error(self) -> None:
        respx.post(f"{BASE}/chat/completions").respond(200, json={"unexpected": True})
        with pytest.raises(ModelProviderError, match="malformed"):
            _provider().complete(_request())

    def test_no_key_raises_model_provider_error(self) -> None:
        with pytest.raises(ModelProviderError, match="OPENAI_API_KEY"):
            _provider(api_key="").complete(_request())

    @respx.mock
    def test_error_log_lines_never_contain_the_clear_key(self, caplog) -> None:
        import logging

        respx.post(f"{BASE}/chat/completions").respond(401, text="unauthorized")
        with (
            caplog.at_level(logging.WARNING, logger="ci_agent.ai.openai"),
            pytest.raises(ModelProviderError),
        ):
            _provider(api_key="sk-topsecretkeyvalue123").complete(_request())
        assert "sk-topsecretkeyvalue123" not in caplog.text
        assert "sk-***" in caplog.text
