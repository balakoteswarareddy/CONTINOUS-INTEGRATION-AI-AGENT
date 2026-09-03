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

GITHUB_PAT_VARIABLE: str = "GITHUB_PAT"
GITHUB_APP_ID_VARIABLE: str = "GITHUB_APP_ID"
GITHUB_APP_PRIVATE_KEY_PATH_VARIABLE: str = "GITHUB_APP_PRIVATE_KEY_PATH"
GITHUB_INSTALLATION_ID_VARIABLE: str = "GITHUB_INSTALLATION_ID"

ADMIN_API_KEY_VARIABLE: str = "ADMIN_API_KEY"
LOCAL_DEV_ADMIN_KEY: str = "ci-agent-local-admin-key"
MAX_CONCURRENT_RUNS_VARIABLE: str = "MAX_CONCURRENT_RUNS_PER_PROJECT"
DEFAULT_MAX_CONCURRENT_RUNS: int = 3

COSIGN_BINARY_VARIABLE: str = "CI_AGENT_COSIGN_BINARY"
DEFAULT_COSIGN_BINARY: str = "cosign"

OPA_URL_VARIABLE: str = "OPA_URL"
DEFAULT_OPA_URL: str = "http://localhost:8181"
OPA_TIMEOUT_VARIABLE: str = "OPA_TIMEOUT_SECONDS"
DEFAULT_OPA_TIMEOUT_SECONDS: float = 5.0
# Dev-only fallback for CI_AGENT_ENV=local, documented in .env.example.
# Never used in dev/prod — those fail startup if the env var is unset.
LOCAL_DEV_WEBHOOK_SECRET: str = "ci-agent-local-dev-webhook-secret"


@dataclass(frozen=True)
class Settings:
    """Runtime settings read from the process environment (Batch 1/2)."""

    env: str = DEFAULT_ENVIRONMENT
    database_url: str = DEFAULT_DATABASE_URL
    github_webhook_secret: str | None = None
    opa_url: str = DEFAULT_OPA_URL
    opa_timeout_seconds: float = DEFAULT_OPA_TIMEOUT_SECONDS
    github_pat: str | None = None
    github_app_id: str | None = None
    github_app_private_key_path: str | None = None
    github_installation_id: str | None = None
    admin_api_key: str | None = None
    max_concurrent_runs_per_project: int = DEFAULT_MAX_CONCURRENT_RUNS
    # Batch 7: real cosign verify wrapper — resolved from PATH unless the
    # env var points at a specific binary (documented in .env.example).
    cosign_binary: str = DEFAULT_COSIGN_BINARY

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
            admin_api_key=_cleaned_env(ADMIN_API_KEY_VARIABLE) or None,
            cosign_binary=os.environ.get(COSIGN_BINARY_VARIABLE, DEFAULT_COSIGN_BINARY),
            max_concurrent_runs_per_project=_int_env(
                MAX_CONCURRENT_RUNS_VARIABLE, DEFAULT_MAX_CONCURRENT_RUNS
            ),
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

    def resolved_admin_api_key(self) -> str:
        """Admin API key for the internal admin endpoints (MVP-grade control).

        ``local`` falls back to a documented dev default; other environments
        must set ``ADMIN_API_KEY`` (startup fails loudly otherwise).
        """
        if self.admin_api_key:
            return self.admin_api_key
        if self.env == "local":
            return LOCAL_DEV_ADMIN_KEY
        raise RuntimeError(
            f"{ADMIN_API_KEY_VARIABLE} must be set when {ENV_VARIABLE} is {self.env!r} "
            "(refusing to expose admin endpoints without a key)"
        )


def _int_env(name: str, default: int) -> int:
    raw = _cleaned_env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _cleaned_env(name: str) -> str:
    """Return the env var value stripped, or "" when unset."""
    return (os.environ.get(name) or "").strip()


def get_settings() -> Settings:
    """Convenience accessor returning environment-derived settings."""
    return Settings.from_environment()
