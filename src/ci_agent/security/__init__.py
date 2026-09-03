"""Security Evidence Service (Batch 6; Report Sections 4.2, 5.1, 9).

Normalizes SAST/SCA/secret-scan tool output into governed findings, persists
them, and feeds real severity counts into the PDP's security_policy
evaluation. Replaces the Batch 5 "one exit-code-only HIGH finding per failed
stage" placeholder — which is fully removed (see NOTES.md).
"""

from ci_agent.security.models import NormalizedFinding, ParseOutcome
from ci_agent.security.parser_registry import (
    UnknownParserError,
    get_parser,
    known_parser_tools,
)
from ci_agent.security.security_evidence_service import SecurityEvidenceService

__all__ = [
    "NormalizedFinding",
    "ParseOutcome",
    "SecurityEvidenceService",
    "UnknownParserError",
    "get_parser",
    "known_parser_tools",
]
