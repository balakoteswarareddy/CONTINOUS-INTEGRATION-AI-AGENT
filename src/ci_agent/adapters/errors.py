"""Vendor-adapter error types.

Lives in its own dependency-free module so reliability code
(``retry_policies``) can classify GitHub errors WITHOUT importing the client
(and therefore without an import cycle).
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


__all__ = ["GitHubAPIError"]
