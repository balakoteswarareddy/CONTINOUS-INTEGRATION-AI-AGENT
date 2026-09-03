"""ResponseValidator — validate model output BEFORE it is used (Batch 9).

A model response is untrusted input (Section 7.3): it may echo injected
instructions, leak secrets, or ignore output limits. Nothing a feature
returns to a user or report passes through unvalidated.

Checks (each failure sets ``valid=False`` with a machine-readable reason):

a. **Policy-bypass signals** (reason ``policy_bypass_attempt``) — any
   suggestion to disable a gate, skip a gate, bypass policy, modify policy
   files, grant exceptions, waive findings, ignore failed gates, approve the
   run, force a merge, or mark a failed run as passed. The full pattern list
   is below, each pattern documented with why it is flagged; this list is
   security-sensitive and must stay reviewable in one place.
b. **Secret patterns** (reason ``secret_in_response``) — the same shared
   pattern list enforced on requests (``ci_agent.ai.models``): a model
   echoing credential material is treated as a leak.
c. **Excessive length** (reason ``excessive_length``) — content longer than
   3x ``max_tokens`` characters: a model that ignores token limits is
   suspicious (possible prompt-injection payload space).

``sanitized_content`` carries the content with every flagged secret AND
policy-bypass pattern replaced by ``[REDACTED]`` — belt and suspenders: even
a ``valid=True`` response is sanitized before it is shown to users.

On a policy-bypass signal the validator also appends the
``ai_response_policy_bypass_detected`` audit event (when an audit store is
supplied) — the response is never used; the calling feature falls back to its
deterministic result.
"""

from __future__ import annotations

import logging
import re

from pydantic import BaseModel, ConfigDict

from ci_agent.ai.models import AIResponse, find_secret_pattern, redact_secret_patterns
from ci_agent.audit.audit_store import AuditStore

LOGGER = logging.getLogger("ci_agent.ai.response_validator")

# Policy-bypass signal patterns (Section 7.3 "Policy bypass: model proposes
# to disable a failed gate"). Each entry documents why it is flagged.
POLICY_BYPASS_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        # Direct proposals to defeat a gate (the canonical threat).
        r"disable (?:the )?(?:security |policy )?gate",
        r"skip (?:the )?(?:security |policy )?gate",
        r"bypass (?:the )?(?:policy|gate|security)",
        # Tampering with the governed contract itself.
        r"modify (?:the )?policy (?:file|files|yaml)",
        r"edit (?:the )?policy (?:file|files|yaml)",
        r"remove (?:the )?(?:policy|gate|security check)",
        # Exception-granting: exceptions come from a separate governed
        # workflow, never from model output.
        r"grant (?:an )?exception",
        r"waive (?:the )?(?:policy|gate|finding|security)",
        # Instructing the operator/platform to ignore enforced outcomes.
        r"ignore (?:all |the )?(?:failed? )?(?:gates?|policies|security)",
        r"mark (?:it|the run) as passed",
        r"approve (?:this|the) run",
        r"force[- ]merge",
    )
)

REDACTED = "[REDACTED]"


class ValidationResult(BaseModel):
    """Outcome of validating one AIResponse."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    reasons: list[str] = []
    sanitized_content: str


class ResponseValidator:
    """Validates model responses before any use."""

    def validate(
        self,
        response: AIResponse,
        feature: str,
        *,
        max_tokens: int,
        audit_store: AuditStore | None = None,
        run_id: str | None = None,
    ) -> ValidationResult:
        """Validate ``response`` for ``feature``; never raises."""
        reasons: list[str] = []

        # (a) policy-bypass signals.
        bypass_hits = [
            pattern.pattern
            for pattern in POLICY_BYPASS_PATTERNS
            if pattern.search(response.content)
        ]
        if bypass_hits:
            reasons.append("policy_bypass_attempt")

        # (b) secret patterns.
        secret_hit = find_secret_pattern(response.content)
        if secret_hit:
            reasons.append("secret_in_response")

        # (c) excessive length (chars vs 3x the token budget — documented
        # approximation of the "model ignored its token limit" signal).
        if len(response.content) > 3 * max_tokens:
            reasons.append("excessive_length")

        # Sanitized content: redact secrets AND bypass language even when
        # valid (belt-and-suspenders before anything reaches a user).
        sanitized = response.content
        for pattern in POLICY_BYPASS_PATTERNS:
            sanitized = pattern.sub(REDACTED, sanitized)
        sanitized = redact_secret_patterns(sanitized)

        if not reasons:
            return ValidationResult(valid=True, reasons=[], sanitized_content=sanitized)

        LOGGER.warning(
            "AI response rejected: feature=%s provider=%s reasons=%s",
            feature,
            response.provider,
            reasons,
        )
        if "policy_bypass_attempt" in reasons and audit_store is not None:
            try:
                audit_store.append_event(
                    run_id or "ai",
                    "ai_response_policy_bypass_detected",
                    {
                        "feature": feature,
                        "provider": response.provider,
                        "reasons": reasons,
                        "bypass_patterns": bypass_hits,
                        "note": "response discarded; feature fell back to a "
                        "deterministic result",
                    },
                )
            except Exception:  # auditing must never break the control plane
                LOGGER.exception("failed to append bypass audit event")
        return ValidationResult(valid=False, reasons=reasons, sanitized_content=sanitized)


__all__ = ["POLICY_BYPASS_PATTERNS", "REDACTED", "ResponseValidator", "ValidationResult"]
