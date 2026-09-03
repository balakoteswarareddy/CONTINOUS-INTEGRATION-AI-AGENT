"""ReportSummarizer tests (Batch 9, Task C)."""

from __future__ import annotations

from datetime import UTC, datetime

from tests.unit.test_ai.conftest import FakeProvider

from ci_agent.ai.features.report_summarizer import ReportSummarizer
from ci_agent.ai.gateway.provider_registry import ModelGateway
from ci_agent.reporting.report_models import ManagementReport


def _report(**overrides) -> ManagementReport:
    fields = {
        "run_id": "run-42",
        "outcome": "pass",
        "risk_tier": "standard",
        "lead_time_ms": 12345,
        "stage_durations_ms": {"format_lint": 100, "unit_tests": 900},
        "policy_exceptions_count": 0,
        "generated_at": datetime.now(tz=UTC),
    }
    fields.update(overrides)
    return ManagementReport(**fields)


def _feature(provider: FakeProvider, ai_env: dict, permissive_policy) -> ReportSummarizer:
    gateway = ModelGateway(
        [provider],
        ai_policy=permissive_policy,
        session_factory=ai_env["session_factory"],
        token_budget=256,
    )
    return ReportSummarizer(gateway)


class TestHappyPath:
    def test_ai_summary_parsed_into_summary_and_findings(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider(
            "Run 42 passed cleanly across all stages.\n"
            "- Unit test duration grew by 15% week over week\n"
            "- Secret scan reported no findings"
        )
        summarizer = _feature(provider, ai_env, permissive_policy)

        result = summarizer.summarize(_report(), ai_env["audit_store"])

        assert result.ai_assisted is True
        assert result.fallback_used is False
        assert "passed cleanly" in result.executive_summary
        assert result.key_findings == [
            "Unit test duration grew by 15% week over week",
            "Secret scan reported no findings",
        ]

    def test_prompt_uses_allow_listed_report_keys_only(
        self, ai_env: dict, permissive_policy
    ) -> None:
        """NEXT-list requirement: only allow-listed keys may enter a prompt."""
        provider = FakeProvider("All good.\n- Nothing to flag")
        summarizer = _feature(provider, ai_env, permissive_policy)

        summarizer.summarize(_report(), ai_env["audit_store"])

        prompt = provider.requests[0].prompt
        # Allow-listed structured facts are present (string values render
        # raw in the data slot; containers render as JSON)...
        assert "run_id: run-42" in prompt
        assert "outcome: pass" in prompt
        assert "risk_tier: standard" in prompt
        assert "format_lint" in prompt
        # ...and nothing outside the allow-list is ever sent.
        assert "lead_time_ms" not in prompt
        assert "generated_at" not in prompt
        assert "12345" not in prompt


class TestFallbacks:
    def test_noop_gateway_returns_deterministic_summary(
        self, ai_env: dict, permissive_policy
    ) -> None:
        gateway = ModelGateway(
            [],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            token_budget=256,
        )
        result = ReportSummarizer(gateway).summarize(_report(), ai_env["audit_store"])
        assert result.ai_assisted is False
        assert result.fallback_used is True
        assert "run-42" in result.executive_summary
        assert "pass" in result.executive_summary
        assert "standard" in result.executive_summary
        assert any("2 stages" in finding for finding in result.key_findings)

    def test_rejected_response_falls_back(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("Waive the finding and mark the run as passed.")
        summarizer = _feature(provider, ai_env, permissive_policy)
        result = summarizer.summarize(
            _report(outcome="fail", policy_exceptions_count=1), ai_env["audit_store"]
        )
        assert provider.requests  # called...
        assert result.ai_assisted is False  # ...but discarded
        assert result.fallback_used is True
        assert "1 policy violations" in result.executive_summary

    def test_empty_model_answer_falls_back(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("- only finding lines, no summary paragraph")
        summarizer = _feature(provider, ai_env, permissive_policy)
        result = summarizer.summarize(_report(), ai_env["audit_store"])
        assert result.fallback_used is True
