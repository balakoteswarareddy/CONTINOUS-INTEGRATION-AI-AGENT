"""Template registry: loads and validates stage templates per stack (Batch 3, Task B).

Every template is validated against
``governance/schemas/stage_template.schema.json`` at load time. There is
intentionally NO default/fallback stack: requesting an unknown stack raises
(:class:`UnknownStackError`) — silently substituting another stack's template
would violate the "no invented behavior" principle (Batch 3 guardrails).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ci_agent.governance import validate_against_schema

TEMPLATES_DIR: Path = Path(__file__).resolve().parent
TEMPLATE_SCHEMA_NAME = "stage_template"


class UnknownStackError(KeyError):
    """No stage template exists for the requested stack (intentional hard fail)."""


class TemplateRegistry:
    """Loads all ``*.yaml`` templates in ``templates/`` and serves them by stack."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self._templates_dir = templates_dir or TEMPLATES_DIR
        self._templates: dict[str, dict[str, Any]] = {}
        for path in sorted(self._templates_dir.glob("*.yaml")):
            payload = self._load(path)
            stack = str(payload["stack"])
            if stack in self._templates:
                raise ValueError(f"Duplicate stage template for stack {stack!r} ({path.name})")
            self._templates[stack] = payload

    @property
    def stacks(self) -> list[str]:
        return sorted(self._templates)

    def get_template(self, stack: str) -> dict[str, Any]:
        """Return the validated template for ``stack``; raises UnknownStackError."""
        try:
            return self._templates[stack]
        except KeyError:
            available = ", ".join(self.stacks)
            raise UnknownStackError(
                f"no stage template for stack {stack!r}; available stacks: {available}"
            ) from None

    def _load(self, path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise ValueError(f"Template file not found: {path}")
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"Expected a top-level mapping in template {path}")
        validate_against_schema(
            payload, schema_name=TEMPLATE_SCHEMA_NAME, label=f"template/{path.name}"
        )
        return payload
