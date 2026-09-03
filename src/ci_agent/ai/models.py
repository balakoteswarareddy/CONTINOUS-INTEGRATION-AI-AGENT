"""AI request/response models + the shared secret-pattern defence (Batch 9).

Pydantic models: ``AIRequest`` (with a HARD construction-time secret check on
``prompt``) and ``AIResponse``. The ORM row for invocation logging lives in
``ci_agent.db.models.AIInvocationRecord``; ``AIInvocationRecordView`` below is
its Pydantic projection.

Secret patterns (the shared defence)
====================================

The same pattern list is enforced at THREE independent layers (defence in
depth, Section 7.3 "data exfiltration"):

1. ``AIRequest``'s ``prompt`` validator — a prompt containing a known secret
   format cannot even be CONSTRUCTED;
2. ``PromptBuilder.build`` — any data value matching the list raises
   ``PromptBuildError`` before a request exists;
3. ``ResponseValidator`` — a model response containing a secret is rejected
   and redacted.

Patterns checked, and why each is here:

- ``-----BEGIN ... PRIVATE KEY-----`` — PEM private key material (TLS, SSH,
  signing keys). Highest-impact credential class in a CI system.
- ``ghp_/gho_/ghu_/ghs_/ghr_`` prefixes — GitHub PAT / user-to-server /
  server-to-server / refresh token family (token-scoped prefixes are
  documented by GitHub precisely so detectors can use them).
- ``glpat-`` — GitLab personal access token.
- ``sk-`` — OpenAI-style API key (and other vendor keys using the prefix).
- ``xox[baprs]-`` — Slack token family.
- ``AKIA`` — AWS access key ID (16 upper alnum chars after the prefix).
- ``AIza`` — Google API key.
- ``Bearer <long-token>`` — raw Authorization headers (incl. JWTs).
- line-anchored ``ALL_CAPS_KEY=`` — env-var-style assignments. Deliberately
  conservative: a log line like ``DATABASE_URL=postgres://...`` is treated as
  potential credential material even when the value looks benign, because
  distinguishing "safe" env assignments from secret ones by value inspection
  is exactly the guess a security boundary must not make.

Every pattern is a compiled regex over plain text — no model, no network, no
heuristics beyond the explicit list. The list is security-sensitive and must
stay reviewable in one place (here).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------
# The shared secret-pattern list (documented in the module docstring).
# --------------------------------------------------------------------------

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
        r"\bgh[posur]_[A-Za-z0-9]{16,}\b",
        r"\bglpat-[A-Za-z0-9_\-]{16,}\b",
        r"\bsk-[A-Za-z0-9_\-]{16,}\b",
        r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bAIza[0-9A-Za-z_\-]{30,}\b",
        r"\bBearer\s+[A-Za-z0-9_\-.]{20,}\b",
        r"(?m)^[A-Z][A-Z0-9_]{2,}=",  # env-var-style assignment (line-anchored)
    )
)

# The four governed AI features (AIRequest.feature must be one of these —
# the fixed allowed set from the Batch 9 spec).
AI_FEATURES: frozenset[str] = frozenset(
    {
        "requirement_normalization",
        "failure_triage",
        "report_summarization",
        "pipeline_explanation",
    }
)

# Classification vocabulary (governance/catalog/data_classification.yaml).
DATA_CLASSIFICATIONS: frozenset[str] = frozenset(
    {"public", "internal", "confidential", "restricted"}
)


def find_secret_pattern(content: str) -> str | None:
    """Return a human-readable description of the first secret pattern found.

    Single detection helper shared by all three enforcement layers so the
    behaviour can never drift between them.
    """
    for pattern in SECRET_PATTERNS:
        match = pattern.search(content)
        if match:
            return f"secret pattern {pattern.pattern!r} matched {match.group(0)[:24]!r}"
    return None


def redact_secret_patterns(content: str) -> str:
    """Replace every secret-pattern match with ``[REDACTED]``."""
    redacted = content
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


# --------------------------------------------------------------------------
# Request / response models
# --------------------------------------------------------------------------


class AIRequest(BaseModel):
    """One governed request to the model gateway.

    ``prompt`` can never contain a raw secret value: construction itself is
    rejected (hard check, not a runtime warning) — see the module docstring
    for the pattern list and rationale.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    feature: str
    prompt: str
    context_classification: str
    max_tokens: int = Field(gt=0)
    temperature: float = Field(ge=0.0, le=1.0, default=0.0)
    provider_hint: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    @field_validator("feature")
    @classmethod
    def _feature_must_be_governed(cls, value: str) -> str:
        if value not in AI_FEATURES:
            allowed = ", ".join(sorted(AI_FEATURES))
            raise ValueError(f"unknown AI feature {value!r}; allowed: {allowed}")
        return value

    @field_validator("context_classification")
    @classmethod
    def _classification_must_be_governed(cls, value: str) -> str:
        if value not in DATA_CLASSIFICATIONS:
            allowed = ", ".join(sorted(DATA_CLASSIFICATIONS))
            raise ValueError(f"unknown data classification {value!r}; allowed: {allowed}")
        return value

    @field_validator("prompt")
    @classmethod
    def _prompt_must_not_contain_secrets(cls, value: str) -> str:
        found = find_secret_pattern(value)
        if found:
            # Hard construction-time rejection (Section 7.3 data-exfiltration
            # control): a prompt with credential material cannot exist.
            raise ValueError(f"AIRequest prompt rejected: {found}")
        return value


class AIResponse(BaseModel):
    """A (possibly fallback) response from the gateway."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    provider: str
    content: str
    tokens_used: int | None = None
    latency_ms: int
    fallback_used: bool
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class AIInvocationRecordView(BaseModel):
    """Pydantic projection of the ``ai_invocation_records`` ORM row.

    Carries hashes, never content: the prompt may contain source code which
    is potentially confidential, so the DB stores ``prompt_hash`` /
    ``response_hash`` only (sha256, ``sha256:...`` format).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int
    run_id: str | None
    feature: str
    provider: str
    context_classification: str
    prompt_hash: str
    response_hash: str
    tokens_used: int | None
    latency_ms: int
    fallback_used: bool
    policy_allowed: bool
    created_at: datetime

    @classmethod
    def from_orm_row(cls, row: Any) -> AIInvocationRecordView:
        return cls(
            id=row.id,
            run_id=row.run_id,
            feature=row.feature,
            provider=row.provider,
            context_classification=row.context_classification,
            prompt_hash=row.prompt_hash,
            response_hash=row.response_hash,
            tokens_used=row.tokens_used,
            latency_ms=row.latency_ms,
            fallback_used=row.fallback_used,
            policy_allowed=row.policy_allowed,
            created_at=row.created_at,
        )


__all__ = [
    "AI_FEATURES",
    "DATA_CLASSIFICATIONS",
    "SECRET_PATTERNS",
    "AIInvocationRecordView",
    "AIRequest",
    "AIResponse",
    "find_secret_pattern",
    "redact_secret_patterns",
]
