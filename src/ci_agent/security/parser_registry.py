"""tool_name -> FindingParser registry (Batch 6, Task B).

A tool named in an ExecutionPlan with NO registered parser is a LOUD error
(:class:`UnknownParserError`), never a silent skip of findings collection —
an unrecognized scanner must not be allowed to look like a clean scan.
"""

from __future__ import annotations

from ci_agent.security.parsers.bandit_parser import BanditParser
from ci_agent.security.parsers.base import FindingParser
from ci_agent.security.parsers.eslint_parser import EslintParser
from ci_agent.security.parsers.gitleaks_parser import GitleaksParser
from ci_agent.security.parsers.npm_audit_parser import NpmAuditParser
from ci_agent.security.parsers.pip_audit_parser import PipAuditParser
from ci_agent.security.parsers.trivy_parser import TrivyParser


class UnknownParserError(KeyError):
    """No parser registered for this tool — fail loudly (Batch 6 Task B)."""


_REGISTRY: dict[str, type[FindingParser]] = {
    BanditParser.tool_name: BanditParser,
    GitleaksParser.tool_name: GitleaksParser,
    PipAuditParser.tool_name: PipAuditParser,
    NpmAuditParser.tool_name: NpmAuditParser,
    EslintParser.tool_name: EslintParser,
    TrivyParser.tool_name: TrivyParser,
}

# Alias table: alternate spellings seen in tool outputs / templates.
_ALIASES: dict[str, str] = {
    "pip_audit": "pip-audit",
    "npmaudit": "npm-audit",
    "npm_audit": "npm-audit",
}


def get_parser(tool_name: str) -> FindingParser:
    """Return the registered parser for ``tool_name`` (or raise)."""
    canonical = _ALIASES.get(tool_name, tool_name)
    parser_cls = _REGISTRY.get(canonical)
    if parser_cls is None:
        raise UnknownParserError(
            f"no findings parser registered for tool {tool_name!r}; "
            f"registered tools: {sorted(_REGISTRY)} — a scan stage whose "
            "output cannot be parsed must fail loudly, never look clean"
        )
    return parser_cls()


def known_parser_tools() -> list[str]:
    return sorted(_REGISTRY)


__all__ = ["UnknownParserError", "get_parser", "known_parser_tools"]
