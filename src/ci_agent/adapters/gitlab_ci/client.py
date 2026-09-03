"""GitLab REST API client for the GitLab CI adapter (Batch 8, Task A).

Uses httpx directly against the GitLab REST API v4 — deliberately no GitLab
SDK, per the vendor-neutrality discipline (Report Section 12): the shared
RunnerAdapter interface must never leak a vendor SDK type. Same
timeout/error/no-logged-credential discipline as the GitHub client.

Auth: a GitLab project access token supplied via the ``GITLAB_ACCESS_TOKEN``
environment variable (resolved by Settings). There is NO default in non-local
environments — constructing a client without a token fails loudly
(:class:`GitLabAPIError`), and the token value is never logged (a redacted
indicator is logged instead). Local dev uses the documented placeholder in
``.env.example``.
"""

from __future__ import annotations

import base64
import logging
from typing import Any
from urllib.parse import quote

import httpx

from ci_agent.adapters.errors import GitLabAPIError
from ci_agent.reliability.retry_policies import retry_transient_external_call

GITLAB_API_BASE_URL = "https://gitlab.com/api/v4"
DEFAULT_TIMEOUT_SECONDS = 10.0

logger = logging.getLogger(__name__)


def _project_path(project_id: str) -> str:
    """URL-encode a project identifier ("group/repo") for a path segment."""
    return quote(project_id, safe="")


class GitLabClient:
    """Thin GitLab REST v4 wrapper used by the adapter and the Observer."""

    def __init__(
        self,
        access_token: str,
        base_url: str = GITLAB_API_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        if not access_token:
            # Fail loud on construction: an unauthenticated client must never
            # exist silently (batch instruction; NOTES.md).
            raise GitLabAPIError("GitLab access token is not configured (set GITLAB_ACCESS_TOKEN)")
        self._access_token = access_token
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._client = client or httpx.Client(base_url=self._base_url, timeout=timeout_seconds)
        logger.info("GitLabClient initialised: gitlab auth: project token (redacted)")

    # ---------------------------------------------------------- requests

    @retry_transient_external_call
    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform an authenticated GitLab API request with explicit error mapping.

        Wrapped with ``retry_transient_external_call`` (same discipline as
        GitHubClient): transport errors and 5xx responses are retried with
        bounded backoff; 4xx responses are NOT (client errors are
        deterministic). Policy decisions are never retried.
        """
        merged = {
            "PRIVATE-TOKEN": self._access_token,
            "Accept": "application/json",
            **(headers or {}),
        }
        try:
            response = self._client.request(method, path, json=json_body, headers=merged)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise GitLabAPIError(f"GitLab request {method} {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise GitLabAPIError(
                f"GitLab request {method} {path} returned HTTP {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )
        return response

    # ------------------------------------------------- repository files

    def create_branch(self, project_id: str, branch: str, ref: str) -> dict[str, Any]:
        """Create ``branch`` pointing at ``ref`` (branch name or commit sha)."""
        response = self.request(
            "POST",
            f"/projects/{_project_path(project_id)}/repository/branches",
            json_body={"branch": branch, "ref": ref},
        )
        return dict(response.json())

    def create_or_update_file(
        self,
        project_id: str,
        file_path: str,
        content: str,
        branch: str,
        commit_message: str,
    ) -> dict[str, Any]:
        """Create (or update) a single file on ``branch`` via the files API.

        GitLab's files API splits create (POST, fails 400 when the file
        already exists on the branch) from update (PUT) — this helper tries
        the create and falls back to the update on that specific conflict.
        """
        project = _project_path(project_id)
        encoded_path = quote(file_path, safe="")
        body: dict[str, Any] = {
            "branch": branch,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "encoding": "base64",
            "commit_message": commit_message,
        }
        try:
            response = self.request(
                "POST", f"/projects/{project}/repository/files/{encoded_path}", json_body=body
            )
        except GitLabAPIError as exc:
            if exc.status_code != 400:
                raise
            response = self.request(
                "PUT", f"/projects/{project}/repository/files/{encoded_path}", json_body=body
            )
        return dict(response.json())

    # ---------------------------------------------------- pipeline ops

    def trigger_pipeline(
        self, project_id: str, ref: str, variables: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Trigger a pipeline on ``ref`` (returns the created pipeline object)."""
        response = self.request(
            "POST",
            f"/projects/{_project_path(project_id)}/pipeline",
            json_body={"ref": ref, "variables": variables or {}},
        )
        return dict(response.json())

    def get_pipeline(self, project_id: str, pipeline_id: str) -> dict[str, Any]:
        """Fetch one pipeline object."""
        response = self.request(
            "GET", f"/projects/{_project_path(project_id)}/pipelines/{pipeline_id}"
        )
        return dict(response.json())

    def get_pipeline_jobs(self, project_id: str, pipeline_id: str) -> list[dict[str, Any]]:
        """List the jobs of a pipeline."""
        response = self.request(
            "GET", f"/projects/{_project_path(project_id)}/pipelines/{pipeline_id}/jobs"
        )
        jobs = response.json()
        return [job for job in jobs if isinstance(job, dict)]

    def list_pipelines(self, project_id: str, ref: str, per_page: int = 10) -> list[dict[str, Any]]:
        """List recent pipelines for ``ref`` (pipeline-id resolution fallback)."""
        response = self.request(
            "GET",
            f"/projects/{_project_path(project_id)}/pipelines"
            f"?ref={quote(ref, safe='')}&per_page={per_page}",
        )
        pipelines = response.json()
        return [p for p in pipelines if isinstance(p, dict)]

    # ---------------------------------------------------- jobs / logs

    def get_job_log(self, project_id: str, job_id: str) -> str:
        """Fetch the raw trace (log) of one job."""
        response = self.request("GET", f"/projects/{_project_path(project_id)}/jobs/{job_id}/trace")
        return response.text

    # ------------------------------------------------- commit statuses

    def post_commit_status(
        self,
        project_id: str,
        sha: str,
        state: str,
        name: str,
        description: str,
    ) -> dict[str, Any]:
        """Post a commit status (the merge-decision publication path on GitLab)."""
        response = self.request(
            "POST",
            f"/projects/{_project_path(project_id)}/statuses/{sha}",
            json_body={"state": state, "name": name, "description": description},
        )
        return dict(response.json())

    def close(self) -> None:
        self._client.close()
