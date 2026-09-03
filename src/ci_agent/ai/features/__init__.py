"""AI-assisted features (Batch 9, Task C; Report Section 13 Phase 4).

Each feature is a thin orchestration layer:
classify -> build prompt -> invoke gateway -> validate response -> return
result OR deterministic fallback. None of them make final decisions.

STANDING RULE for every feature in this package: the output is ADVISORY
ONLY. No feature result is persisted as a policy decision, an approval, or
an evidence record without explicit human confirmation — the AI model is
never the final authority for security, identity, approvals, or release
decisions. Each feature's return path carries a comment stating this.
"""

from __future__ import annotations
