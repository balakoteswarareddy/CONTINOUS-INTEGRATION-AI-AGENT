"""AI guardrails (Batch 9, Task B; Report Sections 6 and 7.3).

These three modules are the mandatory boundary between the rest of the
system and the model gateway: NOTHING sends a request to the gateway without
passing through all three.
"""

from __future__ import annotations
