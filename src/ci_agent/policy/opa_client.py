"""Thin HTTP client wrapper around OPA's REST API (Batch 3, Task A).

Deliberately minimal: one call, ``POST /v1/data/<package>``. Timeouts and
connection failures raise :class:`OPAUnavailableError` specifically so the
PolicyDecisionPoint (and anything downstream) can fail closed explicitly
(Report Section 10 "Timeouts"; Section 18 checklist — an unreachable policy
engine is never an implicit pass).
"""

from __future__ import annotations

from typing import Any

import httpx

DEFAULT_BASE_URL: str = "http://localhost:8181"
DEFAULT_TIMEOUT_SECONDS: float = 5.0


class OPAUnavailableError(RuntimeError):
    """OPA could not be reached, timed out, or returned an unusable response.

    Callers MUST treat this as a policy failure (fail closed), never skip or
    retry-until-pass.
    """


class OPAClient:
    """Minimal sync client for OPA's data REST API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._client = client or httpx.Client(base_url=self._base_url, timeout=timeout_seconds)

    @property
    def base_url(self) -> str:
        return self._base_url

    def evaluate(self, package: str, input_facts: dict[str, Any]) -> dict[str, Any]:
        """POST ``{"input": input_facts}`` to ``/v1/data/<package>``.

        Returns the ``result`` document of the response (empty dict when OPA
        answers without a result — treated as fail-closed by the PDP).
        """
        path = f"/v1/data/{package.strip('/')}"
        try:
            response = self._client.post(path, json={"input": input_facts})
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise OPAUnavailableError(
                f"OPA unreachable at {self._base_url} (timeout={self._timeout_seconds}s): {exc}"
            ) from exc

        if response.status_code != 200:
            raise OPAUnavailableError(
                f"OPA returned HTTP {response.status_code} for {package!r} at {self._base_url}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise OPAUnavailableError(f"OPA returned a non-JSON body for {package!r}") from exc
        result = body.get("result") if isinstance(body, dict) else None
        return result if isinstance(result, dict) else {}

    def close(self) -> None:
        self._client.close()
