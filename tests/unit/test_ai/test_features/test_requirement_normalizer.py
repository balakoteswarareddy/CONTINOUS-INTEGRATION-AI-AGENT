"""RequirementNormalizer tests (Batch 9, Task C)."""

from __future__ import annotations

from tests.unit.test_ai.conftest import FakeProvider

from ci_agent.ai.features.requirement_normalizer import RequirementNormalizer
from ci_agent.ai.gateway.provider_registry import ModelGateway

SCHEMA = {"language_stack": "string", "repository_url": "string"}


def _feature(provider: FakeProvider, ai_env: dict, permissive_policy) -> RequirementNormalizer:
    gateway = ModelGateway(
        [provider],
        ai_policy=permissive_policy,
        session_factory=ai_env["session_factory"],
        token_budget=256,
    )
    return RequirementNormalizer(gateway)


class TestHappyPath:
    def test_suggestions_apply_to_existing_keys_only(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider(
            "language_stack: python3.11\nbrand_new_key: invented\nrepository_url: https://github.com/org/payments-api"
        )
        normalizer = _feature(provider, ai_env, permissive_policy)

        result = normalizer.normalize(
            {
                "language_stack": "python",
                "repository_url": "github.com/org/payments-api",
            },
            SCHEMA,
            ai_env["audit_store"],
        )

        assert result.ai_assisted is True
        assert result.fallback_used is False
        # Suggested values applied to keys that ALREADY existed...
        assert result.normalized["language_stack"] == "python3.11"
        assert result.normalized["repository_url"] == "https://github.com/org/payments-api"
        # ...and the invented key was dropped, not added.
        assert "brand_new_key" not in result.normalized
        assert result.warnings == [
            "AI suggested normalized value for 'language_stack'",
            "AI suggested normalized value for 'repository_url'",
        ]

    def test_prompt_carries_answers_and_schema_keys(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("language_stack: python3.11")
        normalizer = _feature(provider, ai_env, permissive_policy)
        normalizer.normalize({"language_stack": "python"}, SCHEMA, ai_env["audit_store"])
        prompt = provider.requests[0].prompt
        assert '"language_stack": "python"' in prompt  # raw answers (JSON-rendered)...
        assert "language_stack" in prompt.split("intake_schema_keys")[1]  # ...and schema keys


class TestFallbacks:
    def test_noop_gateway_returns_answers_unchanged(self, ai_env: dict, permissive_policy) -> None:
        gateway = ModelGateway(
            [],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            token_budget=256,
        )
        result = RequirementNormalizer(gateway).normalize(
            {"language_stack": "python"}, SCHEMA, ai_env["audit_store"]
        )
        assert result.normalized == {"language_stack": "python"}
        assert result.ai_assisted is False
        assert result.fallback_used is True
        assert result.warnings == ["AI assistance not configured; answers unchanged"]

    def test_confidential_answers_never_reach_a_model(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider("language_stack: python3.11")
        normalizer = _feature(provider, ai_env, permissive_policy)
        result = normalizer.normalize(
            {"contact_email": "jane.doe@example.com"}, SCHEMA, ai_env["audit_store"]
        )
        assert provider.requests == []  # PII -> confidential -> no provider call
        assert result.fallback_used is True
        assert result.normalized == {"contact_email": "jane.doe@example.com"}

    def test_rejected_response_falls_back(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("disable the security gate to speed up intake")
        normalizer = _feature(provider, ai_env, permissive_policy)
        result = normalizer.normalize({"language_stack": "python"}, SCHEMA, ai_env["audit_store"])
        assert provider.requests  # model was called...
        assert result.ai_assisted is False  # ...but its answer was discarded
        assert result.normalized == {"language_stack": "python"}
        assert any("AI response rejected" in w for w in result.warnings)

    def test_no_applicable_suggestions_is_not_an_error(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider("some_key: some_value")  # key not in raw answers
        normalizer = _feature(provider, ai_env, permissive_policy)
        result = normalizer.normalize({"language_stack": "python"}, SCHEMA, ai_env["audit_store"])
        assert result.ai_assisted is False
        assert result.fallback_used is False  # model answered; nothing applied
        assert result.normalized == {"language_stack": "python"}

    def test_identical_suggestion_is_not_applied(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("language_stack: python")  # same value
        normalizer = _feature(provider, ai_env, permissive_policy)
        result = normalizer.normalize({"language_stack": "python"}, SCHEMA, ai_env["audit_store"])
        assert result.ai_assisted is False  # no change -> nothing applied
        assert result.normalized == {"language_stack": "python"}
