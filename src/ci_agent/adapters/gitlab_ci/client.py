"""GitLab REST API client (Batch 8, Task B).

Thin httpx wrapper over the endpoints the adapter needs, following the
GitHubClient's error-mapping discipline: transport errors and 5xx raise a
typed error (retried upstream by the shared tenacity policy only where safe);
4xx raise immediately. The PAT travels in the ``PRIVATE-TOKEN`` header and is
NEVER logged (error messages carry paths and status codes only).
"""

from __future__ import annotations

from typing import Any

import httpx

from ci_agent.reliability.retry_policies import retry_transient_external_call

GITLAB_API_BASE_PATH = "/api/v4"


class GitLabAPIError(RuntimeError):
    """A GitLab API call failed (client error or exhausted transport)."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code

    @property
    def redacted_description(self) -> str:
        """Safe-for-audit description — never includes the token or bodies."""
        code = str(self.status_code) if self.status_code is not None else "transport"
        return f"gitlab api error (http {code}): {str(self)[:120]}"


class GitLabClient:
    """PAT-authenticated GitLab REST client for one configured project."""

    def __init__(
        self,
        base_url: str,
        token: str,
        project_id: str,
        *,
        timeout_seconds: float = 15.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._project_id = project_id
        self._client = http_client or httpx.Client(base_url=self._base_url, timeout=timeout_seconds)

    def close(self) -> None:
        self._client.close()

    @retry_transient_external_call
    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | list[Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Authenticated GitLab API request with explicit error mapping."""
        headers = {"PRIVATE-TOKEN": self._token}
        try:
            response = self._client.request(
                method, path, json=json_body, params=params, headers=headers
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise GitLabAPIError(f"GitLab request {method} {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise GitLabAPIError(
                f"GitLab request {method} {path} returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return response

    # ------------------------------------------------------------ repo/pipeline

    def get_branch_sha(self, branch: str) -> str:
        response = self.request(
            "GET",
            f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/repository/branches/{branch}",
        )
        return str(response.json()["commit"]["id"])

    def create_branch(self, branch: str, ref: str) -> None:
        self.request(
            "POST",
            f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/repository/branches",
            params={"branch": branch, "ref": ref},
        )

    def commit_files(self, branch: str, files: dict[str, str], *, commit_message: str) -> str:
        """Commit one or more files; returns the new commit sha."""
        actions = [
            {"action": "create", "file_path": path, "content": content}
            for path, content in files.items()
        ]
        response = self.request(
            "POST",
            f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/repository/commits",
            json_body={"branch": branch, "commit_message": commit_message, "actions": actions},
        )
        return str(response.json()["id"])

    def create_pipeline(self, branch: str) -> str:
        """Trigger a pipeline on ``branch``; returns the pipeline id."""
        response = self.request(
            "POST",
            f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/pipeline",
            params={"ref": branch},
        )
        return str(response.json()["id"])

    def get_pipeline(self, pipeline_id: str) -> dict[str, Any]:
        response = self.request(
            "GET",
            f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/pipelines/{pipeline_id}",
        )
        return dict(response.json())

    def list_pipeline_jobs(self, pipeline_id: str) -> list[dict[str, Any]]:
        response = self.request(
            "GET",
            f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/pipelines/{pipeline_id}/jobs",
        )
        return list(response.json())

    def get_job_trace(self, job_id: str) -> str:
        response = self.request(
            "GET", f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/jobs/{job_id}/trace"
        )
        return response.text

    def download_job_artifacts(self, job_id: str) -> bytes:
        """The job's artifacts archive (zip bytes)."""
        response = self.request(
            "GET", f"{GITLAB_API_BASE_PATH}/projects/{self._project_id}/jobs/{job_id}/artifacts"
        )
        return response.content


__all__ = ["GitLabAPIError", "GitLabClient"]
