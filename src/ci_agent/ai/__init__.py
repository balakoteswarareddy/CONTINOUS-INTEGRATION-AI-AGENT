"""AI assistance (Batch 9; Report Section 13 Phase 4).

Pluggable model gateway with a no-model fallback (Section 12) and four
AI-assisted features (requirement normalization, failure triage, report
summarization, pipeline explanation) operating under strict data-classification,
tool-boundary, and human-override guardrails (Sections 6, 7.3).

Standing principle for EVERYTHING in this package: the AI model is never the
final authority for security, identity, approvals, or release decisions.
Feature output is advisory only. The platform remains fully functional when
no provider is configured (Section 10/18) — the deterministic fallbacks are
first-class code paths, not error handling.
"""

from __future__ import annotations
