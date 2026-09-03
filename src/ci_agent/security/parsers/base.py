"""FindingParser abstract interface (Batch 6, Task B).

Subclasses implement :meth:`parse_with_status`, which returns a
:class:`ParseOutcome` so "couldn't parse" is ALWAYS distinguishable from
"clean scan" (fail-closed discipline). The plain :meth:`parse` satisfies the
batch's sketched interface for callers that only want findings and treat
warnings upstream.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from ci_agent.security.models import NormalizedFinding, ParseOutcome

LOGGER = logging.getLogger("ci_agent.security.parsers")


class FindingParser(ABC):
    """Parse one tool's raw JSON report into normalized findings."""

    #: Canonical registry key (matches the tool_name used in ExecutionPlans).
    tool_name: ClassVar[str] = ""

    def parse(self, raw_output: str) -> list[NormalizedFinding]:
        """Findings only — the batch's sketched interface."""
        return self.parse_with_status(raw_output).findings

    @abstractmethod
    def parse_with_status(self, raw_output: str) -> ParseOutcome:
        """Parse ``raw_output``; never raise for malformed tool output.

        Malformed/empty JSON yields an EMPTY findings list plus a warning —
        the caller must treat the warning as a fail-closed incident, not as a
        clean scan.
        """

    # ----------------------------------------------------------------- helpers

    @staticmethod
    def _load_json(raw_output: str) -> tuple[Any | None, list[str]]:
        """Defensively JSON-parse tool output; ``(None, warnings)`` on failure."""
        if not raw_output or not raw_output.strip():
            return None, ["empty tool output — not a clean scan"]
        try:
            return json.loads(raw_output), []
        except json.JSONDecodeError as exc:
            LOGGER.warning(
                "tool %s produced unparseable JSON output (%s) — treating as "
                "an incident, not a clean scan",
                "(parser)",  # never log the raw payload
                exc.msg,
            )
            return None, [f"malformed JSON from tool output: {exc.msg}"]

    @staticmethod
    def _warning(message: str) -> ParseOutcome:
        return ParseOutcome(findings=[], warnings=[message])


__all__ = ["FindingParser", "ParseOutcome"]
