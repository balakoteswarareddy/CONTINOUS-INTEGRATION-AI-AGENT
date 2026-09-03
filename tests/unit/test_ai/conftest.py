"""Shared fixtures for the AI test suite (Batch 9).

All tests run with ZERO live providers: fakes record requests, and the
governed policy is a permissive in-memory ``AIPolicy`` (the committed
``ai_policy.yaml`` stays deny-by-default — see NOTES.md).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.ai.errors import ModelProviderError
from ci_agent.ai.gateway.base import ModelProvider
from ci_agent.ai.gateway.provider_registry import ModelGateway
from ci_agent.ai.models import AIRequest, AIResponse
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.policy_spec import AIPolicy
from ci_agent.db.base import Base, create_engine, get_session_factory


class FakeProvider(ModelProvider):
    """Deterministic recording provider (the AI-available test double)."""

    def __init__(
        self,
        content: str = "ok",
        *,
        name: str = "fake",
        fail: bool = False,
        unavailable: bool = False,
    ) -> None:
        self.content = content
        self._name = name
        self.fail = fail
        self.unavailable = unavailable
        self.requests: list[AIRequest] = []

    @property
    def provider_name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return not self.unavailable

    def complete(self, request: AIRequest) -> AIResponse:
        self.requests.append(request)
        if self.fail:
            raise ModelProviderError("configured to fail", provider=self._name)
        return AIResponse(
            request_id=request.request_id,
            provider=self._name,
            content=self.content,
            tokens_used=7,
            latency_ms=3,
            fallback_used=False,
            created_at=datetime.now(tz=UTC),
        )


@pytest.fixture()
def ai_env(tmp_path):  # type: ignore[no-untyped-def]
    engine = create_engine(f"sqlite:///{tmp_path / 'ai-test.db'}")
    Base.metadata.create_all(engine)
    session_factory: sessionmaker[Session] = get_session_factory(engine)
    return {
        "session_factory": session_factory,
        "audit_store": AuditStore(session_factory),
    }


@pytest.fixture()
def permissive_policy() -> AIPolicy:
    """Test policy admitting public+internal content and the fake provider.

    The committed governance file remains deny-by-default; enabling a
    provider/classification is a governed policy change (NOTES.md).
    """
    return AIPolicy(
        allowed_model_providers=["fake", "openai", "anthropic"],
        allowed_data_classification=["public", "internal"],
        require_human_override=True,
    )


@pytest.fixture()
def gateway(ai_env: dict, permissive_policy: AIPolicy) -> ModelGateway:
    return ModelGateway(
        [],
        ai_policy=permissive_policy,
        session_factory=ai_env["session_factory"],
        token_budget=256,
    )
