"""GitHub Actions runner adapter — adapter #1 of many (Report Section 12)."""

from ci_agent.adapters.github_actions.adapter import GitHubActionsAdapter
from ci_agent.adapters.github_actions.command_template_registry import (
    CommandTemplateRegistry,
    UnknownCommandTemplateError,
)
from ci_agent.adapters.github_actions.compiler import compile_to_github_actions

__all__ = [
    "CommandTemplateRegistry",
    "GitHubActionsAdapter",
    "UnknownCommandTemplateError",
    "compile_to_github_actions",
]
