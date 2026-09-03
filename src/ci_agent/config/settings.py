"""Minimal, environment-driven runtime settings (Batch 1 placeholder).

No secrets are read or hardcoded here. Later batches extend this class as
integrations (database, API, runners) arrive. Reads only from the process
environment; defaults to the safest local value.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_VARIABLE: str = "CI_AGENT_ENV"
VALID_ENVIRONMENTS: tuple[str, ...] = ("local", "dev", "prod")
DEFAULT_ENVIRONMENT: str = "local"


@dataclass(frozen=True)
class Settings:
    """Placeholder runtime settings for Batch 1 (Task A)."""

    env: str = DEFAULT_ENVIRONMENT

    @staticmethod
    def from_environment() -> Settings:
        """Build Settings from the process environment, defaulting to ``local``."""
        raw = (os.environ.get(ENV_VARIABLE) or "").strip().lower() or DEFAULT_ENVIRONMENT
        if raw not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"{ENV_VARIABLE} must be one of {', '.join(VALID_ENVIRONMENTS)}; got {raw!r}"
            )
        return Settings(env=raw)


def get_settings() -> Settings:
    """Convenience accessor returning environment-derived settings."""
    return Settings.from_environment()
