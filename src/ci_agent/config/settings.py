"""Minimal, environment-driven runtime settings.

Batch 2 additions: database URL and GitHub webhook secret handling. No secrets
are hardcoded. In non-local environments ``GITHUB_WEBHOOK_SECRET`` must be set
before the ingress app is constructed — startup fails loudly otherwise. The
local environment may fall back to a documented dev-only default so the stack
boots out of the box (CI-Agent Production Architecture Report, Section 7:
secrets live in the environment, never in code).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_VARIABLE: str = "CI_AGENT_ENV"
VALID_ENVIRONMENTS: tuple[str, ...] = ("local", "dev", "prod")
DEFAULT_ENVIRONMENT: str = "local"

DATABASE_URL_VARIABLE: str = "DATABASE_URL"
DEFAULT_DATABASE_URL: str = "sqlite:///./ci_agent.db"

GITHUB_WEBHOOK_SECRET_VARIABLE: str = "GITHUB_WEBHOOK_SECRET"
# Dev-only fallback for CI_AGENT_ENV=local, documented in .env.example.
# Never used in dev/prod — those fail startup if the env var is unset.
LOCAL_DEV_WEBHOOK_SECRET: str = "ci-agent-local-dev-webhook-secret"


@dataclass(frozen=True)
class Settings:
    """Runtime settings read from the process environment (Batch 1/2)."""

    env: str = DEFAULT_ENVIRONMENT
    database_url: str = DEFAULT_DATABASE_URL
    github_webhook_secret: str | None = None

    @staticmethod
    def from_environment() -> Settings:
        """Build Settings from the process environment, defaulting safely."""
        raw = (os.environ.get(ENV_VARIABLE) or "").strip().lower() or DEFAULT_ENVIRONMENT
        if raw not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"{ENV_VARIABLE} must be one of {', '.join(VALID_ENVIRONMENTS)}; got {raw!r}"
            )
        return Settings(
            env=raw,
            database_url=_cleaned_env(DATABASE_URL_VARIABLE) or DEFAULT_DATABASE_URL,
            github_webhook_secret=_cleaned_env(GITHUB_WEBHOOK_SECRET_VARIABLE) or None,
        )

    def resolved_webhook_secret(self) -> bytes:
        """Return the webhook HMAC secret as bytes.

        Resolution order: explicit ``GITHUB_WEBHOOK_SECRET`` env value, then the
        documented dev-only default when ``env == "local"``. Any other
        environment without the variable raises immediately so an insecure
        ingress can never start silently.
        """
        if self.github_webhook_secret:
            return self.github_webhook_secret.encode("utf-8")
        if self.env == "local":
            return LOCAL_DEV_WEBHOOK_SECRET.encode("utf-8")
        raise RuntimeError(
            f"{GITHUB_WEBHOOK_SECRET_VARIABLE} must be set when {ENV_VARIABLE} is "
            f"{self.env!r} (refusing to start the ingress with an unverifiable webhook secret)"
        )


def _cleaned_env(name: str) -> str:
    """Return the env var value stripped, or "" when unset."""
    return (os.environ.get(name) or "").strip()


def get_settings() -> Settings:
    """Convenience accessor returning environment-derived settings."""
    return Settings.from_environment()
