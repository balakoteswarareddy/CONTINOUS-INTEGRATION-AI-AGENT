"""AdapterRouter tests (Batch 8, Task C)."""

from __future__ import annotations

import pytest

from ci_agent.adapters.base import CompiledArtifact, DispatchRef, RunnerAdapter
from ci_agent.adapters.errors import UnknownRunnerError
from ci_agent.adapters.router import AdapterRouter, select_runner_name
from ci_agent.core.models.execution_plan import ExecutionPlan


class _StubAdapter(RunnerAdapter):
    """Minimal concrete adapter for routing tests."""

    def __init__(self, name: str) -> None:
        self.name = name

    def compile(
        self, plan: ExecutionPlan, metadata: dict[str, str] | None = None
    ) -> CompiledArtifact:
        raise NotImplementedError

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        raise NotImplementedError

    def poll_status(self, dispatch_ref: DispatchRef) -> object:
        raise NotImplementedError

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        raise NotImplementedError


class TestGetAdapter:
    def test_returns_the_registered_adapter(self) -> None:
        github = _StubAdapter("github")
        router = AdapterRouter({"github_actions": github})
        assert router.get_adapter("github_actions") is github

    def test_unknown_runner_raises_never_falls_back(self) -> None:
        router = AdapterRouter(
            {"github_actions": _StubAdapter("github")}, default_runner="github_actions"
        )
        with pytest.raises(UnknownRunnerError, match="gitlab_ci"):
            router.get_adapter("gitlab_ci")

    def test_error_message_lists_known_runners(self) -> None:
        router = AdapterRouter({"github_actions": _StubAdapter("g")})
        with pytest.raises(UnknownRunnerError, match="github_actions"):
            router.get_adapter("nope")

    def test_empty_router_raises_for_any_runner(self) -> None:
        router = AdapterRouter()
        with pytest.raises(UnknownRunnerError):
            router.get_adapter("github_actions")


class TestAdapterForProfile:
    def test_default_runner_used_when_profile_runner_is_an_os_string(self) -> None:
        """ProjectProfile.runner carries the runner OS today (linux/windows/
        macos) — the deployment default selects the platform (NOTES.md)."""
        github = _StubAdapter("github")
        router = AdapterRouter({"github_actions": github}, default_runner="github_actions")
        assert router.adapter_for_profile("linux") is github
        assert router.adapter_for_profile(None) is github

    def test_profile_runner_wins_when_it_is_a_registered_platform(self) -> None:
        github = _StubAdapter("github")
        gitlab = _StubAdapter("gitlab")
        router = AdapterRouter(
            {"github_actions": github, "gitlab_ci": gitlab}, default_runner="github_actions"
        )
        assert router.adapter_for_profile("gitlab_ci") is gitlab

    def test_missing_default_registration_fails_loudly(self) -> None:
        """No silent fallback: a misconfigured default raises at plan time."""
        router = AdapterRouter(
            {"gitlab_ci": _StubAdapter("gitlab")}, default_runner="github_actions"
        )
        with pytest.raises(UnknownRunnerError, match="github_actions"):
            router.adapter_for_profile("linux")


class TestRouterMisc:
    def test_register_adds_and_replaces(self) -> None:
        router = AdapterRouter()
        assert router.known_runners == []
        first = _StubAdapter("one")
        second = _StubAdapter("two")
        router.register("github_actions", first)
        assert router.get_adapter("github_actions") is first
        router.register("github_actions", second)
        assert router.get_adapter("github_actions") is second

    def test_select_runner_name_extracts_the_profile_field(self) -> None:
        class _Profile:
            runner = "linux"

        class _Empty:
            pass

        assert select_runner_name(_Profile()) == "linux"
        assert select_runner_name(_Empty()) is None
        assert select_runner_name(None) is None

    def test_repr_lists_runners(self) -> None:
        router = AdapterRouter({"github_actions": _StubAdapter("g")})
        assert "github_actions" in repr(router)


class TestProviderMatrixAlignment:
    def test_router_vocabulary_matches_provider_matrix(self) -> None:
        """The router keys use exactly the provider_matrix runner names."""
        from ci_agent.governance import loader

        matrix = loader.load_provider_matrix()
        assert set(matrix["runner_providers"]) == {"github_actions", "gitlab_ci", "jenkins"}
