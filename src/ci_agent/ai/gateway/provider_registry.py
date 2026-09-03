"""ModelGateway — provider selection, fallback chain, invocation logging.

Batch 9, Task A. The gateway is the ONLY entry point to any model provider:

1. **Classification gate** (Section 7.3 "data exfiltration"): a request whose
   ``context_classification`` is not in ``ai_policy.allowed_data_classification``
   is rejected BEFORE any provider is consulted — zero provider calls, an
   ``ai_policy_rejected`` audit event, an invocation record with
   ``policy_allowed=False``, and a NoopProvider response.
2. **Fallback chain** (Section 10/12): providers are tried in order
   (``is_available()`` then ``complete()``); a :class:`ModelProviderError`
   or an unavailable provider moves to the next; if every configured
   provider fails, the NoopProvider answers with ``fallback_used=True``.
   ``invoke`` NEVER raises — a model outage degrades optional intelligence,
   it never crashes the deterministic CI control plane.
3. **Invocation logging** (Section 6 AI policy "logging"): every invocation,
   regardless of outcome, persists an ``AIInvocationRecord`` carrying the
   sha256 ``prompt_hash``/``response_hash`` — NEVER the prompt or response
   content itself (the prompt may contain confidential source code).

A shared circuit breaker (Batch 5's hand-rolled breaker, same pattern as the
OPA/GitHub clients) may be attached; an open breaker skips provider attempts
entirely (the Noop fallback answers) and ``BreakerOpenError`` never
propagates to callers.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from functools import partial
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ci_agent.ai.errors import ModelProviderError
from ci_agent.ai.gateway.base import ModelProvider
from ci_agent.ai.gateway.noop_provider import NoopProvider
from ci_agent.ai.models import AIRequest, AIResponse
from ci_agent.audit.audit_store import AuditStore
from ci_agent.core.models.policy_spec import AIPolicy
from ci_agent.db.models import AIInvocationRecord, utcnow
from ci_agent.reliability.circuit_breaker import (
    OPEN,
    BreakerOpenError,
    CircuitBreaker,
)

LOGGER = logging.getLogger("ci_agent.ai.gateway")

DEFAULT_TOKEN_BUDGET = 4096


def _sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


class ModelGateway:
    """Ordered provider chain + no-model fallback + invocation logging."""

    def __init__(
        self,
        providers: list[ModelProvider] | None = None,
        *,
        ai_policy: AIPolicy,
        session_factory: sessionmaker[Session],
        token_budget: int = DEFAULT_TOKEN_BUDGET,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self._providers: list[ModelProvider] = list(providers or [])
        self._fallback = NoopProvider()
        self._ai_policy = ai_policy
        self._session_factory = session_factory
        self._token_budget = token_budget
        self._breaker = breaker

    # ------------------------------------------------------------------ info

    @property
    def token_budget(self) -> int:
        """The MODEL_TOKEN_BUDGET setting; the prompt builder truncates to
        it (truncation is logged there, never silently dropped)."""
        return self._token_budget

    @property
    def provider_names(self) -> list[str]:
        return [provider.provider_name for provider in self._providers]

    # ----------------------------------------------------------------- invoke

    def invoke(
        self,
        request: AIRequest,
        audit_store: AuditStore,
        run_id: str | None = None,
    ) -> AIResponse:
        """Answer ``request`` through the guarded fallback chain.

        This method NEVER raises. Every outcome (policy rejection, provider
        failure, fallback) persists an invocation record and returns a valid
        :class:`AIResponse`.
        """
        # Step 1 — classification gate: reject BEFORE any provider is called.
        if request.context_classification not in self._ai_policy.allowed_data_classification:
            LOGGER.info(
                "ai policy rejected feature=%s classification=%s allowed=%s",
                request.feature,
                request.context_classification,
                self._ai_policy.allowed_data_classification,
            )
            fallback_response = self._fallback.complete(request)
            self._record_invocation(request, fallback_response, run_id=run_id, policy_allowed=False)
            self._audit_safely(
                audit_store,
                run_id,
                "ai_policy_rejected",
                {
                    "feature": request.feature,
                    "context_classification": request.context_classification,
                    "allowed_data_classification": list(
                        self._ai_policy.allowed_data_classification
                    ),
                    "note": "request never reached a model provider",
                },
            )
            return fallback_response

        # Step 2 — provider chain in order; breaker guards the attempts.
        response: AIResponse | None = None
        for provider in self._providers:
            if self._breaker is not None and self._breaker.state == OPEN:
                LOGGER.info("model gateway breaker open; skipping provider attempts")
                break
            try:
                if not provider.is_available():
                    LOGGER.info(
                        "model provider %s unavailable; trying next", provider.provider_name
                    )
                    continue
                complete: Callable[[AIRequest], AIResponse] = provider.complete
                if self._breaker is not None:
                    # partial binds the loop-scoped callable immediately —
                    # the breaker can never invoke a later iteration's provider.
                    response = self._breaker.call(partial(complete, request))
                else:
                    response = complete(request)
                break
            except (ModelProviderError, BreakerOpenError) as exc:
                LOGGER.warning(
                    "model provider %s failed (%s); trying next",
                    provider.provider_name,
                    exc,
                )
                continue
            except Exception:  # defensive: the gateway must never raise
                LOGGER.exception("unexpected model provider failure")
                continue

        # Step 3 — no-model fallback (NoopProvider always succeeds).
        if response is None:
            response = self._fallback.complete(request)

        # Step 4 — every invocation is logged (hashes, never content).
        self._record_invocation(request, response, run_id=run_id, policy_allowed=True)
        return response

    # --------------------------------------------------------------- plumbing

    def _record_invocation(
        self,
        request: AIRequest,
        response: AIResponse,
        *,
        run_id: str | None,
        policy_allowed: bool,
    ) -> None:
        record = AIInvocationRecord(
            run_id=run_id,
            feature=request.feature,
            provider=response.provider,
            context_classification=request.context_classification,
            prompt_hash=_sha256(request.prompt),
            response_hash=_sha256(response.content),
            tokens_used=response.tokens_used,
            latency_ms=response.latency_ms,
            fallback_used=response.fallback_used,
            policy_allowed=policy_allowed,
            created_at=utcnow(),
        )
        try:
            with self._session_factory() as session:
                session.add(record)
                session.commit()
        except Exception:  # logging must never break the control plane
            LOGGER.exception("failed to persist AIInvocationRecord")

    def _audit_safely(
        self,
        audit_store: AuditStore,
        run_id: str | None,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        try:
            audit_store.append_event(run_id or "ai", event_type, payload)
        except Exception:  # auditing must never break the control plane
            LOGGER.exception("failed to append AI audit event %s", event_type)


def build_gateway(
    *,
    ai_policy: AIPolicy,
    session_factory: sessionmaker[Session],
    provider_setting: str,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    breaker: CircuitBreaker | None = None,
) -> ModelGateway:
    """Build the deployment's gateway from the ``AI_PROVIDER`` setting.

    ``noop`` (the default) registers no external provider — the system is
    fully functional before any API key is configured. ``openai`` /
    ``anthropic`` register the corresponding HTTP provider, but ONLY if the
    provider is also admitted by ``ai_policy.allowed_model_providers`` — the
    committed governance file lists none (deny-by-default), so enabling a
    provider is a governed policy change, not just an env var. Providers not
    admitted (or selected without credentials) are skipped with a clear log
    line and the Noop fallback serves requests.
    """
    providers: list[ModelProvider] = []
    if provider_setting == "noop":
        LOGGER.info("AI_PROVIDER=noop: no external model provider configured")
        return ModelGateway(
            ai_policy=ai_policy,
            session_factory=session_factory,
            token_budget=token_budget,
            breaker=breaker,
        )

    candidate: ModelProvider
    if provider_setting == "openai":
        from ci_agent.ai.gateway.openai_provider import OpenAIProvider

        candidate = OpenAIProvider()
    elif provider_setting == "anthropic":
        from ci_agent.ai.gateway.anthropic_provider import AnthropicProvider

        candidate = AnthropicProvider()
    else:
        LOGGER.warning("unknown AI_PROVIDER=%r; using noop fallback", provider_setting)
        return ModelGateway(
            ai_policy=ai_policy,
            session_factory=session_factory,
            token_budget=token_budget,
            breaker=breaker,
        )

    if candidate.provider_name not in ai_policy.allowed_model_providers:
        LOGGER.warning(
            "AI_PROVIDER=%s is not in ai_policy.allowed_model_providers=%s "
            "(deny-by-default); not registering it — Noop fallback will serve",
            provider_setting,
            ai_policy.allowed_model_providers,
        )
        return ModelGateway(
            ai_policy=ai_policy,
            session_factory=session_factory,
            token_budget=token_budget,
            breaker=breaker,
        )
    if not candidate.is_available():
        LOGGER.warning(
            "AI_PROVIDER=%s selected but unavailable (missing key or unreachable); "
            "Noop fallback will serve",
            provider_setting,
        )
    providers.append(candidate)
    return ModelGateway(
        providers,
        ai_policy=ai_policy,
        session_factory=session_factory,
        token_budget=token_budget,
        breaker=breaker,
    )


__all__ = ["DEFAULT_TOKEN_BUDGET", "ModelGateway", "build_gateway"]
