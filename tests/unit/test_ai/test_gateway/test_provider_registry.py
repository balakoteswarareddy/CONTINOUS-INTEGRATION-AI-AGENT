"""ModelGateway tests (Batch 9, Task A): policy gate, fallback chain,
invocation logging, breaker behaviour, factory."""

from __future__ import annotations

import hashlib

from sqlalchemy import select
from tests.unit.test_ai.conftest import FakeProvider

from ci_agent.ai.gateway.noop_provider import NoopProvider
from ci_agent.ai.gateway.provider_registry import ModelGateway, build_gateway
from ci_agent.ai.models import AIRequest
from ci_agent.core.models.policy_spec import AIPolicy
from ci_agent.db.models import AIInvocationRecord
from ci_agent.reliability.circuit_breaker import CircuitBreaker


def _request(classification: str = "internal", feature: str = "failure_triage") -> AIRequest:
    return AIRequest(
        feature=feature,
        prompt="Explain the failure for the record.",
        context_classification=classification,
        max_tokens=64,
    )


class TestClassificationGate:
    def test_disallowed_classification_never_reaches_a_provider(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        provider = FakeProvider()
        gateway = ModelGateway(
            [provider], ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        response = gateway.invoke(_request("confidential"), ai_env["audit_store"], run_id=None)
        assert provider.requests == []  # ZERO provider calls
        assert response.fallback_used is True
        assert response.provider == "noop"

    def test_policy_rejection_is_audited_and_recorded(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        gateway = ModelGateway(
            [], ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        gateway.invoke(_request("restricted"), ai_env["audit_store"], run_id=None)
        trail = ai_env["audit_store"].get_audit_trail("ai")
        assert any(e.event_type == "ai_policy_rejected" for e in trail)
        with ai_env["session_factory"]() as session:
            records = list(session.execute(select(AIInvocationRecord)).scalars())
        assert len(records) == 1
        assert records[0].policy_allowed is False
        assert records[0].provider == "noop"

    def test_allowed_classification_reaches_the_provider(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        provider = FakeProvider(content="explanation")
        gateway = ModelGateway(
            [provider], ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        response = gateway.invoke(_request("internal"), ai_env["audit_store"], run_id=None)
        assert len(provider.requests) == 1
        assert response.content == "explanation"
        assert response.fallback_used is False


class TestFallbackChain:
    def test_unavailable_provider_falls_through_to_next(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        first = FakeProvider(unavailable=True, name="down")
        second = FakeProvider(content="from-second", name="up")
        gateway = ModelGateway(
            [first, second], ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        response = gateway.invoke(_request(), ai_env["audit_store"], run_id=None)
        assert first.requests == []
        assert response.provider == "up"

    def test_provider_error_falls_through_to_next(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        first = FakeProvider(fail=True, name="broken")
        second = FakeProvider(content="ok", name="healthy")
        gateway = ModelGateway(
            [first, second], ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        response = gateway.invoke(_request(), ai_env["audit_store"], run_id=None)
        assert response.provider == "healthy"

    def test_all_providers_failing_degrades_to_noop(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        providers = [FakeProvider(fail=True, name=f"p{i}") for i in range(3)]
        gateway = ModelGateway(
            providers, ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        response = gateway.invoke(_request(), ai_env["audit_store"], run_id=None)
        assert response.fallback_used is True
        assert response.provider == "noop"

    def test_invoke_never_raises_even_when_everything_is_broken(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        class _Hostile:
            provider_name = "hostile"

            def is_available(self) -> bool:
                raise RuntimeError("availability check exploded")

            def complete(self, request: AIRequest):  # type: ignore[no-untyped-def]
                raise RuntimeError("complete exploded")

        gateway = ModelGateway(
            [_Hostile()],  # type: ignore[list-item]
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
        )
        response = gateway.invoke(_request(), ai_env["audit_store"], run_id=None)
        assert response.fallback_used is True


class TestInvocationLogging:
    def test_record_carries_hashes_never_content(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        provider = FakeProvider(content="secret-free explanation")
        gateway = ModelGateway(
            [provider], ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        request = _request()
        gateway.invoke(request, ai_env["audit_store"], run_id="run-1")
        with ai_env["session_factory"]() as session:
            records = list(session.execute(select(AIInvocationRecord)).scalars())
        assert len(records) == 1
        record = records[0]
        expected_prompt_hash = f"sha256:{hashlib.sha256(request.prompt.encode()).hexdigest()}"
        expected_response_hash = f"sha256:{hashlib.sha256(b'secret-free explanation').hexdigest()}"
        assert record.prompt_hash == expected_prompt_hash
        assert record.response_hash == expected_response_hash
        assert record.feature == "failure_triage"
        assert record.run_id == "run-1"
        assert record.policy_allowed is True
        assert record.fallback_used is False
        assert record.tokens_used == 7
        # The content itself is NEVER persisted.
        with ai_env["session_factory"]() as session:
            rows = list(session.execute(select(AIInvocationRecord.prompt_hash)))
        assert all("Explain the failure" not in str(row) for row in rows)

    def test_every_outcome_logs_a_record(self, ai_env: dict, permissive_policy: AIPolicy) -> None:
        gateway = ModelGateway(
            [FakeProvider(fail=True)],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
        )
        gateway.invoke(_request(), ai_env["audit_store"], run_id=None)  # provider failure
        gateway.invoke(_request("confidential"), ai_env["audit_store"], run_id=None)  # rejection
        with ai_env["session_factory"]() as session:
            count = len(list(session.execute(select(AIInvocationRecord))))
        assert count == 2

    def test_persistence_failure_never_breaks_invoke(self, permissive_policy: AIPolicy) -> None:
        class _BrokenFactory:
            def __call__(self):  # pragma: no cover - exercised via failure path
                raise RuntimeError("db down")

        gateway = ModelGateway(
            [],
            ai_policy=permissive_policy,
            session_factory=_BrokenFactory(),  # type: ignore[arg-type]
        )

        class _NullAudit:
            def append_event(self, *args: object, **kwargs: object) -> None:
                return None

        response = gateway.invoke(_request(), _NullAudit(), run_id=None)  # type: ignore[arg-type]
        assert response.fallback_used is True


class TestBreakerIntegration:
    def test_open_breaker_skips_providers_entirely(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        provider = FakeProvider(content="never-reached")
        breaker = CircuitBreaker(
            "model_gateway", failure_threshold=1, recovery_timeout_seconds=60.0
        )
        gateway = ModelGateway(
            [provider],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            breaker=breaker,
        )
        breaker.state = "open"
        breaker.opened_at = float("inf")  # never recovers during the test
        response = gateway.invoke(_request(), ai_env["audit_store"], run_id=None)
        assert provider.requests == []
        assert response.provider == "noop"  # BreakerOpenError never propagated


class TestFactory:
    def test_noop_setting_registers_no_external_provider(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        gateway = build_gateway(
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            provider_setting="noop",
        )
        assert gateway.provider_names == []

    def test_provider_not_in_policy_allowlist_is_not_registered(self, ai_env: dict) -> None:
        deny_all = AIPolicy(
            allowed_model_providers=[],  # committed posture: none approved
            allowed_data_classification=["public"],
            require_human_override=True,
        )
        gateway = build_gateway(
            ai_policy=deny_all,
            session_factory=ai_env["session_factory"],
            provider_setting="openai",
        )
        assert gateway.provider_names == []  # deny-by-default wins

    def test_unknown_provider_setting_falls_back_to_noop(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        gateway = build_gateway(
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            provider_setting="grok",
        )
        assert gateway.provider_names == []

    def test_token_budget_property(self, ai_env: dict, permissive_policy: AIPolicy) -> None:
        gateway = ModelGateway(
            [],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            token_budget=99,
        )
        assert gateway.token_budget == 99

    def test_noop_provider_used_as_fallback_instance(
        self, ai_env: dict, permissive_policy: AIPolicy
    ) -> None:
        gateway = ModelGateway(
            [], ai_policy=permissive_policy, session_factory=ai_env["session_factory"]
        )
        response = gateway.invoke(_request("public"), ai_env["audit_store"], run_id=None)
        assert response.provider == NoopProvider().provider_name
