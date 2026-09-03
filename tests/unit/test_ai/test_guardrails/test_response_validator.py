"""ResponseValidator tests (Batch 9, Task B)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ci_agent.ai.guardrails.response_validator import ResponseValidator
from ci_agent.ai.models import AIResponse


@pytest.fixture()
def validator() -> ResponseValidator:
    return ResponseValidator()


def _response(content: str, provider: str = "fake") -> AIResponse:
    return AIResponse(
        request_id="req-1",
        provider=provider,
        content=content,
        tokens_used=5,
        latency_ms=1,
        fallback_used=False,
        created_at=datetime.now(tz=UTC),
    )


class TestPolicyBypass:
    @pytest.mark.parametrize(
        "content",
        [
            "You should disable the security gate to unblock the pipeline.",
            "Just skip the gate this once.",
            "An admin can bypass the policy by editing the config.",
            "Modify the policy file to raise the threshold.",
            "We can grant an exception for this finding.",
            "Waive the finding and continue.",
            "Ignore the failed gate and merge anyway.",
            "Approve this run despite the findings.",
            "Force-merge the branch.",
            "Mark the run as passed manually.",
        ],
    )
    def test_bypass_language_is_flagged(self, validator: ResponseValidator, content: str) -> None:
        result = validator.validate(_response(content), "failure_triage", max_tokens=256)
        assert result.valid is False
        assert "policy_bypass_attempt" in result.reasons

    def test_bypass_is_audited(self, validator: ResponseValidator, ai_env: dict) -> None:
        result = validator.validate(
            _response("disable the security gate"),
            "failure_triage",
            max_tokens=256,
            audit_store=ai_env["audit_store"],
            run_id="run-1",
        )
        assert result.valid is False
        trail = ai_env["audit_store"].get_audit_trail("run-1")
        assert any(e.event_type == "ai_response_policy_bypass_detected" for e in trail)

    def test_bypass_content_is_redacted_in_sanitized_output(
        self, validator: ResponseValidator
    ) -> None:
        result = validator.validate(
            _response("Please disable the security gate now."), "failure_triage", max_tokens=256
        )
        assert "[REDACTED]" in result.sanitized_content
        assert "disable the security gate" not in result.sanitized_content


class TestSecretsInResponse:
    def test_secret_in_response_is_flagged(self, validator: ResponseValidator) -> None:
        result = validator.validate(
            _response("the credential is ghp_AbCdEf123456789012345"),
            "report_summarization",
            max_tokens=256,
        )
        assert result.valid is False
        assert "secret_in_response" in result.reasons
        assert "ghp_" not in result.sanitized_content

    def test_private_key_in_response_is_flagged(self, validator: ResponseValidator) -> None:
        result = validator.validate(
            _response("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"),
            "failure_triage",
            max_tokens=256,
        )
        assert result.valid is False
        assert "secret_in_response" in result.reasons


class TestExcessiveLength:
    def test_oversized_response_is_flagged(self, validator: ResponseValidator) -> None:
        result = validator.validate(_response("x" * 4000), "pipeline_explanation", max_tokens=128)
        assert result.valid is False
        assert "excessive_length" in result.reasons

    def test_reasonable_length_passes(self, validator: ResponseValidator) -> None:
        result = validator.validate(_response("a" * 100), "pipeline_explanation", max_tokens=128)
        assert result.valid is True


class TestCleanResponses:
    def test_clean_response_is_valid_and_unredacted(self, validator: ResponseValidator) -> None:
        content = "The lint stage failed because three imports are unused. Fix them and re-run."
        result = validator.validate(_response(content), "failure_triage", max_tokens=256)
        assert result.valid is True
        assert result.reasons == []
        assert result.sanitized_content == content  # no false redactions


class TestCombined:
    def test_multiple_reasons_accumulate(self, validator: ResponseValidator) -> None:
        result = validator.validate(
            _response("disable the gate and use glpat-AbCdEf123456789012345"),
            "failure_triage",
            max_tokens=256,
        )
        assert set(result.reasons) == {"policy_bypass_attempt", "secret_in_response"}

    def test_validation_never_raises_on_any_content(self, validator: ResponseValidator) -> None:
        for content in ("", "\x00", "normal text", "disable " * 100):
            result = validator.validate(_response(content), "failure_triage", max_tokens=64)
            assert isinstance(result.valid, bool)
