"""Vendor-adapter error types.

Lives in its own dependency-free module so reliability code
(``retry_policies``) can classify adapter errors WITHOUT importing the client
(and therefore without an import cycle). Batch 8 adds the GitLab/Jenkins
error types and the router's UnknownRunnerError alongside GitHub's — every
adapter exception lives here, none scattered into client modules.
"""

from __future__ import annotations


class GitHubAPIError(RuntimeError):
    """A GitHub REST call failed at the HTTP or transport level.

    Carries the HTTP ``status_code`` (None for transport errors/timeouts) and
    the (redacted-safe) response ``body`` so callers can branch on status
    instead of parsing messages. Never raised for auth-side configuration
    problems only — those raise before any request is attempted.
    """

    def __init__(
        self, message: str, status_code: int | None = None, body: str | None = None
    ) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(message)


class GitLabAPIError(RuntimeError):
    """A GitLab REST call failed at the HTTP or transport level (Batch 8).

    Same shape and discipline as :class:`GitHubAPIError`: ``status_code`` is
    None for transport errors/timeouts, ``body`` is redacted-safe, and the
    token value is NEVER part of the message (tested).
    """

    def __init__(
        self, message: str, status_code: int | None = None, body: str | None = None
    ) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(message)


class JenkinsAPIError(RuntimeError):
    """A Jenkins REST call failed at the HTTP or transport level (Batch 8).

    Same shape and discipline as :class:`GitHubAPIError`.
    """

    def __init__(
        self, message: str, status_code: int | None = None, body: str | None = None
    ) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(message)


class UnknownRunnerError(KeyError):
    """No adapter is registered for the requested runner (Batch 8, Task C).

    Raised by :class:`ci_agent.adapters.router.AdapterRouter` at plan time —
    the run must fail LOUDLY here (parked in ERROR by the orchestrators),
    never silently proceed with a different runner. KeyError base mirrors
    UnknownCommandTemplateError (allow-list lookup miss).
    """


__all__ = [
    "GitHubAPIError",
    "GitLabAPIError",
    "JenkinsAPIError",
    "UnknownRunnerError",
]
