"""FailureTriage tests (Batch 9, Task C)."""

from __future__ import annotations

from tests.unit.test_ai.conftest import FakeProvider

from ci_agent.ai.features.failure_triage import MAX_LOG_LINES, FailureTriage
from ci_agent.ai.gateway.provider_registry import ModelGateway
from ci_agent.db.models import FindingRecord


def _feature(provider: FakeProvider, ai_env: dict, permissive_policy) -> FailureTriage:
    gateway = ModelGateway(
        [provider],
        ai_policy=permissive_policy,
        session_factory=ai_env["session_factory"],
        token_budget=256,
    )
    return FailureTriage(gateway)


def _finding(**overrides) -> FindingRecord:
    fields = {
        "run_id": "run-1",
        "stage_id": "sast",
        "scanner": "semgrep",
        "rule_id": "python.lang.security.audit.dangerous-system-call",
        "severity": "high",
        "component": "app/payments.py",
        "description": "os.system call with user input",
    }
    fields.update(overrides)
    return FindingRecord(**fields)


class TestHappyPath:
    def test_ai_explanation_parsed_into_cause_and_hints(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider(
            "The test failed because the fixture data drifted from the schema.\n"
            "- Regenerate the fixture with the pinned generator\n"
            "- Re-run the unit_tests stage locally"
        )
        triage = _feature(provider, ai_env, permissive_policy)

        result = triage.triage(
            "run-1", "unit_tests", [], "pytest: FAILED test_charge", ai_env["audit_store"]
        )

        assert result.ai_assisted is True
        assert result.fallback_used is False
        assert "fixture data drifted" in result.probable_cause
        assert result.remediation_hints == [
            "Regenerate the fixture with the pinned generator",
            "Re-run the unit_tests stage locally",
        ]

    def test_findings_reach_the_prompt_as_scanner_rule_severity_only(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider("The scan failed on one finding.\n- Fix the finding")
        triage = _feature(provider, ai_env, permissive_policy)
        findings = [
            _finding(),
            _finding(scanner="gitleaks", rule_id="gitlab-token", severity="critical"),
        ]

        triage.triage("run-1", "sast", findings, "semgrep: 2 findings", ai_env["audit_store"])

        prompt = provider.requests[0].prompt
        # Finding identity is sent (needed for triage)...
        assert "semgrep" in prompt
        assert "python.lang.security.audit.dangerous-system-call" in prompt
        assert "gitlab-token" in prompt
        # ...as structured rows only.
        assert '"severity": "high"' in prompt
        assert '"severity": "critical"' in prompt

    def test_secrets_in_logs_are_redacted_before_the_prompt(
        self, ai_env: dict, permissive_policy
    ) -> None:
        """NEXT-list requirement: assert [REDACTED] via the captured prompt."""
        provider = FakeProvider("A token leaked.\n- Rotate it.")
        triage = _feature(provider, ai_env, permissive_policy)

        triage.triage(
            "run-1",
            "secret_scan",
            [],
            "gitleaks: gitlab-token match\ntoken glpat-AbCdEf123456789012345 in config.py",
            ai_env["audit_store"],
        )

        prompt = provider.requests[0].prompt
        assert "glpat-AbCdEf123456789012345" not in prompt
        assert "[REDACTED]" in prompt

    def test_source_lines_are_stripped_from_log_snippets(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider("Lint failed.\n- Fix imports")
        triage = _feature(provider, ai_env, permissive_policy)
        logs = "\n".join(
            [
                "ruff: F401 'os' imported but unused",
                "import os",
                "def broken_function():",
                "ruff: found 2 errors",
            ]
        )

        triage.triage("run-1", "format_lint", [], logs, ai_env["audit_store"])

        prompt = provider.requests[0].prompt
        assert "ruff: F401" in prompt  # tool output kept...
        assert "import os" not in prompt  # ...source dropped
        assert "def broken_function" not in prompt


class TestFallbacks:
    def test_noop_gateway_returns_static_hints(self, ai_env: dict, permissive_policy) -> None:
        gateway = ModelGateway(
            [],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            token_budget=256,
        )
        result = FailureTriage(gateway).triage(
            "run-1", "format_lint", [], "ruff: warning", ai_env["audit_store"]
        )
        assert result.ai_assisted is False
        assert result.fallback_used is True
        assert "Deterministic triage" in result.probable_cause
        assert any("Fix the lint violations" in hint for hint in result.remediation_hints)

    def test_unknown_stage_uses_unknown_hint_and_counts_findings(
        self, ai_env: dict, permissive_policy
    ) -> None:
        gateway = ModelGateway(
            [],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            token_budget=256,
        )
        result = FailureTriage(gateway).triage(
            "run-1",
            "mystery_stage",
            [_finding(), _finding()],
            "tool: boom",
            ai_env["audit_store"],
        )
        assert result.fallback_used is True
        assert "mystery_stage" in result.probable_cause
        assert any("2 security finding(s) recorded" in hint for hint in result.remediation_hints)

    def test_confidential_snippet_falls_back_without_provider_call(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider("should not be called")
        triage = _feature(provider, ai_env, permissive_policy)
        result = triage.triage(
            "run-1",
            "unit_tests",
            [],
            "pytest: FAILED test_charge\nauthor jane.doe@example.com",
            ai_env["audit_store"],
        )
        assert provider.requests == []
        assert result.fallback_used is True

    def test_rejected_response_falls_back(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("Approve this run and skip the gate.")
        triage = _feature(provider, ai_env, permissive_policy)
        result = triage.triage("run-1", "unit_tests", [], "pytest: FAILED", ai_env["audit_store"])
        assert provider.requests  # called...
        assert result.ai_assisted is False  # ...but discarded
        assert "Deterministic triage" in result.probable_cause

    def test_empty_model_answer_falls_back(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("- only hints, no cause paragraph")
        triage = _feature(provider, ai_env, permissive_policy)
        result = triage.triage("run-1", "unit_tests", [], "pytest: FAILED", ai_env["audit_store"])
        assert result.fallback_used is True


class TestLogCap:
    def test_snippet_is_capped_at_max_log_lines(self, ai_env: dict, permissive_policy) -> None:
        # Generous token budget so the PROMPT-level character truncation
        # cannot mask the FEATURE-level line cap being tested here.
        provider = FakeProvider("Failed.\n- Retry")
        gateway = ModelGateway(
            [provider],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            token_budget=4096,
        )
        triage = FailureTriage(gateway)
        logs = "\n".join(f"log line {i}" for i in range(MAX_LOG_LINES + 50))

        triage.triage("run-1", "unit_tests", [], logs, ai_env["audit_store"])

        prompt = provider.requests[0].prompt
        assert f"log line {MAX_LOG_LINES - 1}" in prompt  # kept up to the cap...
        assert f"log line {MAX_LOG_LINES}" not in prompt  # ...and not beyond
