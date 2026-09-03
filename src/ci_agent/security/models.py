"""Normalized security findings (Batch 6; Report Sections 4.2, 5.1, 9).

``NormalizedFinding`` aligns field-for-field with the Batch 1
``EvidenceModel.Finding`` shape (severity, scanner, rule_id, component,
disposition) plus parse-side detail (description, location) that the evidence
rows keep. It is the tool-agnostic currency of the Security Evidence Service:
parsers emit it, the service persists it, the PDP and reports consume it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ci_agent.core.models.common import Severity


class NormalizedFinding(BaseModel):
    """One tool finding normalized into the governed vocabulary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Severity
    scanner: str
    rule_id: str
    component: str | None = None
    description: str = ""
    # "file:line" when the tool reports a location.
    location: str | None = None
    disposition: str = Field(default="open")


class ParseOutcome(BaseModel):
    """Result of parsing one raw tool output.

    ``warnings`` is deliberately distinct from an empty ``findings`` list: a
    tool that produced no VALID output is NOT a clean scan (Batch 6, fail-
    closed discipline). Each warning is a short machine-readable string (no
    raw tool payload — it may contain sensitive data).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    findings: list[NormalizedFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """True only when parsing succeeded AND zero findings were found."""
        return not self.findings and not self.warnings


__all__ = ["NormalizedFinding", "ParseOutcome"]
