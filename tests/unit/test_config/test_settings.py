"""Unit tests for the minimal env-driven Settings class (Batch 1, Task A)."""

from __future__ import annotations

import pytest

from ci_agent.config.settings import ENV_VARIABLE, Settings, get_settings


class TestSettings:
    def test_defaults_to_local(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV_VARIABLE, raising=False)

        settings = get_settings()
        assert settings.env == "local"

    def test_reads_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_VARIABLE, "dev")
        assert get_settings().env == "dev"

        monkeypatch.setenv(ENV_VARIABLE, "prod")
        assert get_settings().env == "prod"

    def test_value_is_case_insensitive_and_trimmed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_VARIABLE, "  PROD  ")
        assert get_settings().env == "prod"

    def test_empty_value_falls_back_to_local(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_VARIABLE, "")
        assert get_settings().env == "local"

    def test_invalid_environment_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_VARIABLE, "staging")

        with pytest.raises(ValueError, match="CI_AGENT_ENV"):
            get_settings()

    def test_settings_is_immutable(self) -> None:
        settings = Settings()
        with pytest.raises(Exception):  # noqa: B017 - dataclasses.FrozenInstanceError
            settings.env = "prod"  # type: ignore[misc]
