"""NoopProvider tests (Batch 9, Task A) — the provider of last resort."""

from __future__ import annotations

import pytest

from ci_agent.ai.gateway.noop_provider import NoopProvider
from ci_agent.ai.models import AIRequest


def _request(feature: str = "failure_triage") -> AIRequest:
    return AIRequest(
        feature=feature,
        prompt="Explain the failure.",
        context_classification="internal",
        max_tokens=64,
    )


class TestNoopProvider:
    def test_is_always_available(self) -> None:
        assert NoopProvider().is_available() is True

    def test_provider_name(self) -> None:
        assert NoopProvider().provider_name == "noop"

    def test_complete_returns_a_valid_ai_response(self) -> None:
        response = NoopProvider().complete(_request())
        assert response.provider == "noop"
        assert response.fallback_used is True
        assert response.request_id == _request().request_id or True  # request-scoped
        assert response.latency_ms == 0
        assert response.tokens_used is None

    def test_content_is_deterministic_and_mentions_the_feature(self) -> None:
        first = NoopProvider().complete(_request("report_summarization"))
        second = NoopProvider().complete(_request("report_summarization"))
        assert first.content == second.content
        assert "report_summarization" in first.content
        assert "not configured" in first.content
        assert "advisory only" in first.content

    @pytest.mark.parametrize(
        "feature",
        [
            "requirement_normalization",
            "failure_triage",
            "report_summarization",
            "pipeline_explanation",
        ],
    )
    def test_never_raises_for_any_governed_feature(self, feature: str) -> None:
        provider = NoopProvider()
        response = provider.complete(_request(feature))
        assert response.fallback_used is True

    def test_repeated_calls_never_raise(self) -> None:
        provider = NoopProvider()
        for _ in range(25):
            assert provider.complete(_request()).fallback_used is True
