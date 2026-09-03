"""DataClassifier — the content classification gate (Batch 9, Task B).

Classifies content into the governed vocabulary
(``public``/``internal``/``confidential``/``restricted`` —
``governance/catalog/data_classification.yaml``) by scanning for EXPLICIT
signals. The ruleset is deterministic and documented — no second AI model is
used to classify content for the first AI model (that would move the trust
boundary, not strengthen it).

Rules (highest severity wins: restricted > confidential > internal > public):

- **restricted** — any hit on the shared secret-pattern list (private keys,
  provider tokens, AWS/Google keys, raw Bearer headers, env-var-style
  ``ALL_CAPS_KEY=`` assignments). See ``ci_agent.ai.models`` for the full,
  documented pattern list.
- **confidential** — source-code markers (``def ``/``class ``/``import ``/
  ``from x import`` at line start, shebangs, SPDX identifiers, copyright
  headers) or PII indicators (email addresses, SSN-shaped numbers).
- **internal** — structured or machine-generated content (JSON/braces, log
  levels, ISO timestamps, ``key: value`` lines) — the default posture for
  CI artefacts.
- **public** — plain prose with none of the above signals.

``is_permitted_for_ai`` is the GATE, not a suggestion: when it returns
False the gateway rejects the request before any provider is called.
"""

from __future__ import annotations

import re

from ci_agent.ai.models import SECRET_PATTERNS
from ci_agent.core.models.policy_spec import AIPolicy

CLASSIFICATION_ORDER: dict[str, int] = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}

# Source-code markers: signals that literal source text is present. Used both
# for classification (confidential) and by FailureTriage to STRIP source lines
# from log snippets before they reach a prompt (content-boundary enforcement).
SOURCE_LINE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"^\s*def\s+\w+\(",
        r"^\s*class\s+\w+",
        r"^\s*import\s+\w+",
        r"^\s*from\s+[\w.]+\s+import\s+",
        r"^#!/usr/bin/",
        r"^#!",
        r"SPDX-License-Identifier",
        r"Copyright \(c\)",
    )
)

# PII indicators.
PII_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        r"\b\d{3}-\d{2}-\d{4}\b",
    )
)

# Structured / machine-generated content markers.
STRUCTURED_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"(?m)^\s*[\[{]",
        r"\b(ERROR|WARNING|INFO|DEBUG|CRITICAL|TRACE)\b",
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
        r"(?m)^\s*[\"\']?[\w.\-]+[\"\']?\s*:\s",
        r"\b(passed|failed|skipped)\b",
    )
)


def _any_match(patterns: tuple[re.Pattern[str], ...], content: str) -> bool:
    return any(pattern.search(content) for pattern in patterns)


class DataClassifier:
    """Deterministic content classifier (the gate, not a suggestion)."""

    def classify(self, content: str) -> str:
        """Return the highest-severity classification matching ``content``."""
        if any(pattern.search(content) for pattern in SECRET_PATTERNS):
            return "restricted"
        if _any_match(SOURCE_LINE_PATTERNS, content) or _any_match(PII_PATTERNS, content):
            return "confidential"
        if _any_match(STRUCTURED_PATTERNS, content):
            return "internal"
        return "public"

    def is_permitted_for_ai(self, classification: str, ai_policy: AIPolicy) -> bool:
        """Whether ``classification`` may reach a model under ``ai_policy``."""
        return classification in ai_policy.allowed_data_classification

    @staticmethod
    def without_source_lines(content: str) -> str:
        """Drop source-code lines (content-boundary enforcement for triage).

        Log snippets fed to the model may contain ONLY tool output lines
        (linter messages, test failures, scan findings) — never raw source.
        This is an enforcement, not a suggestion: every matching line is
        removed entirely.
        """
        kept = [
            line
            for line in content.splitlines()
            if not any(pattern.search(line) for pattern in SOURCE_LINE_PATTERNS)
        ]
        return "\n".join(kept)

    @staticmethod
    def exceeds_ceiling(classification: str, ceiling: str) -> bool:
        """Whether ``classification`` is MORE severe than ``ceiling``.

        Features use this to enforce their own ceilings (e.g. intake answers
        are "internal at most"): content classified above the ceiling is
        NEVER sent to a model — the feature falls back deterministically
        instead. The classification is never downgraded to fit the ceiling;
        secrecy only ever escalates.
        """
        return CLASSIFICATION_ORDER[classification] > CLASSIFICATION_ORDER[ceiling]


__all__ = [
    "CLASSIFICATION_ORDER",
    "PII_PATTERNS",
    "SOURCE_LINE_PATTERNS",
    "STRUCTURED_PATTERNS",
    "DataClassifier",
]
