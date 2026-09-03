"""Retry policy tests (Batch 5): transient-only scope, bounded attempts."""

from __future__ import annotations

import httpx
import pytest

from ci_agent.adapters.errors import GitHubAPIError
from ci_agent.reliability.retry_policies import (
    MAX_ATTEMPTS,
    retry_transient_external_call,
)


class _Counter:
    def __init__(self) -> None:
        self.calls = 0


@retry_transient_external_call
def _flaky(counter: _Counter, fail_times: int, error: BaseException) -> str:
    counter.calls += 1
    if counter.calls <= fail_times:
        raise error
    return "ok"


@retry_transient_external_call
def _always_fails(counter: _Counter, error: BaseException) -> str:
    counter.calls += 1
    raise error


def test_connect_error_is_retried_then_succeeds() -> None:
    counter = _Counter()
    error = httpx.ConnectError("connection refused")
    assert _flaky(counter, 2, error) == "ok"
    assert counter.calls == 3


def test_timeout_is_retried() -> None:
    counter = _Counter()
    assert _flaky(counter, 1, httpx.ReadTimeout("timed out")) == "ok"
    assert counter.calls == 2


def test_github_5xx_is_retried() -> None:
    counter = _Counter()
    error = GitHubAPIError("boom", status_code=502, body="bad gateway")
    assert _flaky(counter, 1, error) == "ok"
    assert counter.calls == 2


def test_github_4xx_is_never_retried() -> None:
    counter = _Counter()
    error = GitHubAPIError("nope", status_code=404, body="not found")
    with pytest.raises(GitHubAPIError):
        _always_fails(counter, error)
    assert counter.calls == 1  # no retry on client errors


def test_github_transport_error_is_retried() -> None:
    counter = _Counter()
    error = GitHubAPIError("timeout", status_code=None, body="")
    assert _flaky(counter, 1, error) == "ok"
    assert counter.calls == 2


def test_attempts_are_bounded() -> None:
    counter = _Counter()
    error = httpx.ConnectError("still down")
    with pytest.raises(httpx.ConnectError):  # reraise=True: original error
        _always_fails(counter, error)
    assert counter.calls == MAX_ATTEMPTS


def test_arbitrary_errors_are_not_retried() -> None:
    counter = _Counter()
    with pytest.raises(RuntimeError):
        _always_fails(counter, RuntimeError("bug"))
    assert counter.calls == 1


def test_policy_decisions_are_structurally_never_retried() -> None:
    """Inspection test (batch DoD): the PDP gate method has NO retry decorator.

    A policy/security decision is a decision, not a transient failure —
    Section 10 forbids retrying it. The decorator exists only on
    ``OPAClient.evaluate`` (transport) and ``GitHubClient.request``.
    """
    import inspect

    from ci_agent.policy.policy_decision_point import PolicyDecisionPoint

    source = inspect.getsource(PolicyDecisionPoint.evaluate_gate)
    assert "retry" not in source.lower()
    evaluate = PolicyDecisionPoint.evaluate_gate
    assert not hasattr(evaluate, "retry")  # no tenacity attachment
    assert not hasattr(evaluate, "wraps")
