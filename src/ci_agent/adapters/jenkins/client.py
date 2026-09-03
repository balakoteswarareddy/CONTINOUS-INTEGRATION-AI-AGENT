"""Jenkins REST API client (Batch 8, Task C).

Basic-auth (user + API token) httpx wrapper over the endpoints the adapter
needs. Status model: the Pipeline Steps/`wfapi` plugin endpoints
(``.../wfapi/describe``) report per-stage status — the standard declarative
pipeline introspection. The token NEVER appears in error messages or logs.
"""

from __future__ import annotations

from typing import Any

import httpx

from ci_agent.reliability.retry_policies import retry_transient_external_call


class JenkinsAPIError(RuntimeError):
    """A Jenkins API call failed (client error or exhausted transport)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code

    @property
    def redacted_description(self) -> str:
        code = str(self.status_code) if self.status_code is not None else "transport"
        return f"jenkins api error (http {code}): {str(self)[:120]}"


class JenkinsClient:
    """API-token-authenticated Jenkins REST client for one configured job."""

    def __init__(
        self,
        base_url: str,
        user: str,
        api_token: str,
        job_name: str,
        *,
        timeout_seconds: float = 15.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (user, api_token)
        self._job_name = job_name
        self._client = http_client or httpx.Client(base_url=self._base_url, timeout=timeout_seconds)

    def close(self) -> None:
        self._client.close()

    @retry_transient_external_call
    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            response = self._client.request(
                method, path, json=json_body, auth=self._auth, headers=headers or {}
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise JenkinsAPIError(f"Jenkins request {method} {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise JenkinsAPIError(
                f"Jenkins request {method} {path} returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return response

    # --------------------------------------------------------------- job/build

    def job_path(self) -> str:
        return f"/job/{self._job_name}"

    def trigger_build(self, parameters: dict[str, str] | None = None) -> str:
        """Start a build; returns the queue item location (build resolves async)."""
        path = (
            f"{self.job_path()}/buildWithParameters" if parameters else f"{self.job_path()}/build"
        )
        response = self.request("POST", path)
        location: str = str(response.headers.get("Location", ""))
        if not location:
            raise JenkinsAPIError("Jenkins build trigger returned no queue location")
        return location

    def get_queue_item(self, queue_location: str) -> dict[str, Any]:
        path = queue_location.split(self._base_url, 1)[-1]
        response = self.request("GET", f"{path}{'/' if not path.endswith('/') else ''}api/json")
        return dict(response.json())

    def get_build(self, build_number: str) -> dict[str, Any]:
        response = self.request("GET", f"{self.job_path()}/{build_number}/api/json")
        return dict(response.json())

    def describe_build_stages(self, build_number: str) -> list[dict[str, Any]]:
        """Per-stage status via the pipeline steps ``wfapi`` endpoints."""
        response = self.request("GET", f"{self.job_path()}/{build_number}/wfapi/describe")
        payload = response.json()
        stages: list[dict[str, Any]] = []
        for stage in payload.get("stages", []) or []:
            stages.append(dict(stage))
        return stages

    def download_artifact(self, build_number: str, artifact_path: str) -> bytes:
        response = self.request("GET", f"{self.job_path()}/{build_number}/artifact/{artifact_path}")
        return response.content


__all__ = ["JenkinsAPIError", "JenkinsClient"]
