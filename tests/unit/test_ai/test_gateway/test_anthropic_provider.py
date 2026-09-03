"""Anthropic provider tests (Batch 9, Task A) — respx-mocked HTTP, zero creds.

Verifies the Anthropic messages API SHAPE specifically (x-api-key +
anthropic-version headers, REQUIRED top-level max_tokens, content-block
response, input+output usage) — not a wrapped OpenAI shape.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from ci_agent.ai.errors import ModelProviderError
from ci_agent.ai.gateway.anthropic_provider import AnthropicProvider
from ci_agent.ai.models import AIRequest

BASE = "https://api.anthropic.test/v1"


def _request() -> AIRequest:
    return AIRequest(
        feature="pipeline_explanation",
        prompt="Explain the pipeline.",
        context_classification="public",
        max_tokens=96,
        temperature=0.0,
    )


def _provider(**kwargs: object) -> AnthropicProvider:
    kwargs.setdefault("api_key", "sk-ant-test-0123456789")
    kwargs.setdefault("base_url", BASE)
    return AnthropicProvider(**kwargs)  # type: ignore[arg-type]


class TestAuthAndShape:
    @respx.mock
    def test_requests_carry_x_api_key_and_version_headers(self) -> None:
        route = respx.post(f"{BASE}/messages").respond(
            200,
            json={
                "content": [{"type": "text", "text": "explanation"}],
                "usage": {"input_tokens": 10, "output_tokens": 4},
            },
        )
        response = _provider().complete(_request())
        headers = route.calls[0].request.headers
        assert headers["x-api-key"] == "sk-ant-test-0123456789"
        assert headers["anthropic-version"] == "2023-06-01"
        assert "Authorization" not in headers
        assert response.content == "explanation"
        assert response.tokens_used == 14

    @respx.mock
    def test_max_tokens_is_a_required_top_level_body_field(self) -> None:
        route = respx.post(f"{BASE}/messages").respond(
            200,
            json={"content": [{"type": "text", "text": "x"}], "usage": {}},
        )
        _provider().complete(_request())
        body = json.loads(route.calls[0].request.content)
        assert body["max_tokens"] == 96
        assert body["messages"] == [{"role": "user", "content": "Explain the pipeline."}]
        assert body["temperature"] == 0.0

    @respx.mock
    def test_joins_multiple_text_content_blocks(self) -> None:
        respx.post(f"{BASE}/messages").respond(
            200,
            json={
                "content": [
                    {"type": "text", "text": "part one; "},
                    {"type": "tool_use", "id": "t1"},  # non-text blocks skipped
                    {"type": "text", "text": "part two"},
                ],
                "usage": {"input_tokens": 3, "output_tokens": 3},
            },
        )
        assert _provider().complete(_request()).content == "part one; part two"


class TestAvailability:
    @respx.mock
    def test_available_on_models_200(self) -> None:
        respx.get(f"{BASE}/models").respond(200, json={"data": []})
        assert _provider().is_available() is True

    @respx.mock
    def test_unavailable_on_error_never_raises(self) -> None:
        respx.get(f"{BASE}/models").respond(503, text="down")
        assert _provider().is_available() is False

    @respx.mock
    def test_unavailable_on_transport_error(self) -> None:
        respx.get(f"{BASE}/models").mock(side_effect=httpx.ConnectError("nope"))
        assert _provider().is_available() is False

    def test_missing_key_is_unavailable(self) -> None:
        assert AnthropicProvider(api_key="", base_url=BASE).is_available() is False


class TestComplete:
    @respx.mock
    def test_http_error_raises_model_provider_error_with_status(self) -> None:
        respx.post(f"{BASE}/messages").respond(529, text="overloaded")
        with pytest.raises(ModelProviderError) as excinfo:
            _provider().complete(_request())
        assert excinfo.value.status_code == 529
        assert excinfo.value.provider == "anthropic"

    @respx.mock
    def test_timeout_raises_model_provider_error(self) -> None:
        respx.post(f"{BASE}/messages").mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(ModelProviderError, match="timed out"):
            _provider().complete(_request())

    @respx.mock
    def test_malformed_response_raises_model_provider_error(self) -> None:
        respx.post(f"{BASE}/messages").respond(200, json={"content": "not-a-list"})
        with pytest.raises(ModelProviderError, match="malformed"):
            _provider().complete(_request())

    def test_no_key_raises_model_provider_error(self) -> None:
        with pytest.raises(ModelProviderError, match="ANTHROPIC_API_KEY"):
            _provider(api_key="").complete(_request())
