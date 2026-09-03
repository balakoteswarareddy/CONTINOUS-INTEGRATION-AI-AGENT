"""AdapterRouter tests (Batch 8, Task A; Section 12 multi-runner scale)."""

from __future__ import annotations

from typing import Any

import pytest

from ci_agent.adapters.base import CompiledArtifact, DispatchRef, RunnerStatusSnapshot, StageStatus
from ci_agent.adapters.router import (
    EXECUTION_LOCATION_TO_PROVIDER,
    AdapterRouter,
    RunnerUnavailableError,
    UnknownRunnerProviderError,
)
from ci_agent.reliability.circuit_breaker import CircuitBreaker


class _RecordingAdapter:
    provider = "unset"

    def __init__(self, name: str, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.calls: list[str] = []

    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> CompiledArtifact:
        self.calls.append("compile")
        if self.fail:
            raise RuntimeError(f"{self.name} is down")
        return CompiledArtifact(kind=self.name, content="x", content_hash="h")

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        self.calls.append("dispatch")
        if self.fail:
            raise RuntimeError(f"{self.name} is down")
        return DispatchRef(run_id=run_id, repository="r", branch="b")

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        self.calls.append("poll")
        if self.fail:
            raise RuntimeError(f"{self.name} is down")
        return RunnerStatusSnapshot(
            run_id=dispatch_ref.run_id,
            dispatch_ref=dispatch_ref,
            status=StageStatus.RUNNING,
            completed=False,
        )

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        self.calls.append("logs")
        return f"{self.name}:{step_id}"


def _plan(provider_key: str = "run-gh-1") -> Any:
    class _Plan:
        run_id = provider_key

    return _Plan()


def _router(**adapters: _RecordingAdapter) -> AdapterRouter:
    return AdapterRouter(
        dict(adapters),  # type: ignore[arg-type]
        lambda run_id: EXECUTION_LOCATION_TO_PROVIDER.get(run_id, run_id),
        breakers={
            name: CircuitBreaker(
                f"runner:{name}", failure_threshold=2, recovery_timeout_seconds=60.0
            )
            for name in adapters
        },
    )


class TestSelection:
    def test_routes_by_provider(self) -> None:
        gh = _RecordingAdapter("gh")
        gl = _RecordingAdapter("gl")
        router = _router(github_actions=gh, gitlab_ci=gl)
        artifact = router.compile(_plan("github_hosted"), {"repository": "r", "source_sha": "s"})
        assert artifact.kind == "gh"
        artifact = router.compile(_plan("gitlab_hosted"), {"repository": "r", "source_sha": "s"})
        assert artifact.kind == "gl"
        assert gh.calls == ["compile"] and gl.calls == ["compile"]

    def test_unknown_provider_is_loud_no_fallback(self) -> None:
        gh = _RecordingAdapter("gh")
        router = _router(github_actions=gh)
        with pytest.raises(UnknownRunnerProviderError, match="never falling back"):
            router.compile(_plan("gitlab_hosted"), {"repository": "r", "source_sha": "s"})
        assert gh.calls == []

    def test_dispatch_stamps_provider_on_ref(self) -> None:
        gh = _RecordingAdapter("gh")
        router = _router(github_actions=gh)
        artifact = router.compile(_plan("github_hosted"), {"repository": "r", "source_sha": "s"})
        ref = router.dispatch(artifact, "github_hosted")
        assert ref.provider == "github_actions"


class TestFailureIsolation:
    def test_open_gitlab_breaker_leaves_github_flowing(self) -> None:
        gl = _RecordingAdapter("gl", fail=True)
        gh = _RecordingAdapter("gh")
        router = _router(github_actions=gh, gitlab_ci=gl)

        # Two consecutive GitLab failures open ITS breaker (threshold 2).
        for _ in range(2):
            with pytest.raises(RuntimeError, match="gl is down"):
                router.compile(_plan("gitlab_hosted"), {"repository": "r", "source_sha": "s"})

        # GitLab is now circuit-open -> typed unavailability, no call attempt.
        with pytest.raises(RunnerUnavailableError, match=r"gitlab_ci.*unavailable"):
            router.compile(_plan("gitlab_hosted"), {"repository": "r", "source_sha": "s"})

        # GitHub is UNAFFECTED — isolation is the whole point.
        artifact = router.compile(_plan("github_hosted"), {"repository": "r", "source_sha": "s"})
        assert artifact.kind == "gh"
        ref = router.dispatch(artifact, "github_hosted")
        assert ref.provider == "github_actions"
        snapshot = router.poll_status(ref)
        assert snapshot.status is StageStatus.RUNNING
