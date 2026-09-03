"""Command template registry — the executable-command allow-list (Batch 4, Task A).

Every shell command in a compiled workflow comes from a lookup in
``command_templates.yaml``. Unknown ids raise :class:`UnknownCommandTemplateError`
— there is NO dynamic command construction from free-form tool names, ever
(Section 7.3: "enforce command schemas, argument validation and allow-lists").
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

TEMPLATES_FILE: Path = Path(__file__).resolve().parent / "command_templates.yaml"


class UnknownCommandTemplateError(KeyError):
    """The requested command_template_id is not in the allow-list (hard fail)."""


def load_command_templates(path: Path | None = None) -> dict[str, str | None]:
    """Load and minimally validate the allow-listed command templates."""
    template_path = path or TEMPLATES_FILE
    payload: Any = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Command template file must be a mapping: {template_path}")
    for key, value in payload.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"Invalid command template id: {key!r}")
        if value is not None and not isinstance(value, str):
            raise ValueError(
                f"Command for {key!r} must be a string or null; got {type(value).__name__}"
            )
    return dict(payload)


class CommandTemplateRegistry:
    """Lookup table for allow-listed commands, keyed by command_template_id."""

    def __init__(self, templates: dict[str, str | None] | None = None) -> None:
        self._templates = templates if templates is not None else load_command_templates()

    @property
    def known_ids(self) -> list[str]:
        return sorted(self._templates)

    def get_command(self, command_template_id: str) -> str | None:
        """Return the allow-listed command for ``command_template_id``.

        Returns ``None`` for natively-handled steps (e.g. ``checkout.default``
        -> actions/checkout). Raises :class:`UnknownCommandTemplateError` for
        unknown ids — never guess or construct a command.
        """
        try:
            return self._templates[command_template_id]
        except KeyError:
            known = ", ".join(self.known_ids)
            raise UnknownCommandTemplateError(
                f"command template {command_template_id!r} is not allow-listed; known ids: {known}"
            ) from None
