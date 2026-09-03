"""GitHub REST API client for the GitHub Actions adapter (Batch 4, Task A).

Uses httpx directly against the GitHub REST API v3 — deliberately no GitHub
SDK, per the vendor-neutrality discipline (Report Section 12): the shared
RunnerAdapter interface must never leak a vendor SDK type.

Auth (MVP, per batch instructions):
- ``GITHUB_PAT`` — fine-grained PAT passthrough (documented fallback), or
- ``GITHUB_APP_ID`` + ``GITHUB_APP_PRIVATE_KEY_PATH`` + ``GITHUB_INSTALLATION_ID``
  — GitHub App JWT -> installation token exchange (preferred).

Hardening note (NOTES.md): full workload-identity/OIDC hardening of this
credential (Report Section 7.2) is revisited before production go-live; the
MVP uses a securely-stored, scoped credential — never hardcoded, never logged
(a redacted indicator is logged instead).
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt

GITHUB_API_BASE_URL = "https://api.github.com"
DEFAULT_TIMEOUT_SECONDS = 10.0
APP_TOKEN_TTL_SECONDS = 600
TOKEN_EXPIRY_MARGIN_SECONDS = 60

logger = logging.getLogger(__name__)


class GitHubAPIError(RuntimeError):
    """A GitHub API call failed (non-2xx, timeout, or unusable response).

    Carries the HTTP status code and response body (when available). Never
    raised as a bare exception — callers can catch this type specifically.
    """

    def __init__(
        self, message: str, status_code: int | None = None, body: str | None = None
    ) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(message)


@dataclass(frozen=True)
class GitHubAuthConfig:
    """Adapter credentials, resolved from Settings by the caller.

    Exactly one of ``pat`` or (``app_id`` + ``private_key_path`` +
    ``installation_id``) must be provided.
    """

    pat: str | None = None
    app_id: str | None = None
    private_key_path: str | None = None
    installation_id: str | None = None

    def redacted_description(self) -> str:
        """A safe, loggable indicator — never contains credential material."""
        if self.pat:
            return "github auth: PAT (redacted)"
        if self.app_id and self.private_key_path and self.installation_id:
            return (
                f"github auth: GitHub App id={self.app_id} "
                f"installation={self.installation_id} (key redacted)"
            )
        return "github auth: not configured"


class GitHubClient:
    """Thin GitHub REST wrapper used by the adapter and the Observer."""

    def __init__(
        self,
        auth: GitHubAuthConfig,
        base_url: str = GITHUB_API_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        self._auth = auth
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._client = client or httpx.Client(base_url=self._base_url, timeout=timeout_seconds)
        self._cached_token: str | None = None
        self._cached_token_expiry: float = 0.0
        logger.info("GitHubClient initialised: %s", auth.redacted_description())

    # ------------------------------------------------------------- auth

    def _private_key(self) -> bytes:
        if not self._auth.private_key_path:
            raise GitHubAPIError("GitHub App private key path is not configured")
        return Path(self._auth.private_key_path).read_bytes()

    def _app_jwt(self) -> str:
        """Sign a short-lived GitHub App JWT (RS256)."""
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + APP_TOKEN_TTL_SECONDS, "iss": self._auth.app_id}
        return jwt.encode(payload, self._private_key(), algorithm="RS256")

    def _installation_token(self) -> str:
        """Exchange the App JWT for an installation access token (cached)."""
        now = time.time()
        if self._cached_token and now < self._cached_token_expiry:
            return self._cached_token
        if not self._auth.installation_id:
            raise GitHubAPIError("GitHub installation id is not configured")
        try:
            response = self._client.post(
                f"/app/installations/{self._auth.installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {self._app_jwt()}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise GitHubAPIError(f"GitHub installation-token exchange failed: {exc}") from exc
        if response.status_code != 201:
            raise GitHubAPIError(
                f"GitHub installation-token exchange failed: HTTP {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )
        token = str(response.json().get("token", ""))
        if not token:
            raise GitHubAPIError("GitHub installation-token response contained no token")
        self._cached_token = token
        self._cached_token_expiry = now + APP_TOKEN_TTL_SECONDS - TOKEN_EXPIRY_MARGIN_SECONDS
        return token

    def _auth_header(self) -> dict[str, str]:
        if self._auth.pat:
            return {"Authorization": f"Bearer {self._auth.pat}"}
        return {"Authorization": f"Bearer {self._installation_token()}"}

    # ---------------------------------------------------------- requests

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform an authenticated GitHub API request with explicit error mapping."""
        merged = {"Accept": "application/vnd.github+json", **self._auth_header(), **(headers or {})}
        try:
            response = self._client.request(method, path, json=json_body, headers=merged)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise GitHubAPIError(f"GitHub request {method} {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise GitHubAPIError(
                f"GitHub request {method} {path} returned HTTP {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )
        return response

    # ------------------------------------------------- file / repo ops

    def get_branch_sha(self, repo: str, branch: str) -> str:
        """Return the head commit sha of ``branch``."""
        response = self.request("GET", f"/repos/{repo}/git/ref/heads/{branch}")
        return str(response.json()["object"]["sha"])

    def create_branch(self, repo: str, branch_name: str, from_sha: str) -> None:
        """Create ``branch_name`` pointing at ``from_sha`` (409-free for MVP)."""
        self.request(
            "POST",
            f"/repos/{repo}/git/refs",
            json_body={"ref": f"refs/heads/{branch_name}", "sha": from_sha},
        )

    def create_or_update_file(
        self, repo: str, path: str, content: str, branch: str, message: str
    ) -> dict[str, Any]:
        """Create (or update) a single file on ``branch`` via the contents API."""
        payload_sha: str | None = None
        try:
            existing = self.request("GET", f"/repos/{repo}/contents/{path}?ref={branch}")
            payload_sha = str(existing.json().get("sha") or "") or None
        except GitHubAPIError as exc:
            if exc.status_code != 404:
                raise

        body = {
            "message": message,
            "branch": branch,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        }
        if payload_sha:
            body["sha"] = payload_sha
        response = self.request("PUT", f"/repos/{repo}/contents/{path}", json_body=body)
        return dict(response.json())

    def trigger_workflow_dispatch(
        self, repo: str, workflow_file: str, ref: str, inputs: dict[str, str] | None = None
    ) -> None:
        """Trigger ``workflow_dispatch`` for ``workflow_file`` on ``ref``."""
        self.request(
            "POST",
            f"/repos/{repo}/actions/workflows/{workflow_file}/dispatches",
            json_body={"ref": ref, "inputs": inputs or {}},
        )

    # ---------------------------------------------------- run polling

    def get_workflow_run(self, repo: str, run_id: str) -> dict[str, Any]:
        """Fetch one workflow run object."""
        response = self.request("GET", f"/repos/{repo}/actions/runs/{run_id}")
        return dict(response.json())

    def list_workflow_runs_for_branch(
        self, repo: str, branch: str, per_page: int = 10
    ) -> list[dict[str, Any]]:
        """List recent workflow runs for ``branch`` (to resolve the run id)."""
        response = self.request(
            "GET", f"/repos/{repo}/actions/runs?branch={branch}&per_page={per_page}"
        )
        runs = response.json().get("workflow_runs", [])
        return [run for run in runs if isinstance(run, dict)]

    def get_check_runs(self, repo: str, ref: str) -> list[dict[str, Any]]:
        """List check runs for a commit sha/branch ref."""
        response = self.request("GET", f"/repos/{repo}/commits/{ref}/check-runs")
        runs = response.json().get("check_runs", [])
        return [run for run in runs if isinstance(run, dict)]

    def post_check_run(
        self,
        repo: str,
        sha: str,
        name: str,
        status: str,
        conclusion: str | None = None,
        output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create or update a check run (the merge-decision publication path)."""
        body: dict[str, Any] = {"name": name, "head_sha": sha, "status": status}
        if conclusion is not None:
            body["conclusion"] = conclusion
        if output is not None:
            body["output"] = output
        response = self.request("POST", f"/repos/{repo}/check-runs", json_body=body)
        return dict(response.json())

    # ------------------------------------------------------- artifacts

    def list_artifacts(self, repo: str, run_id: str) -> list[dict[str, Any]]:
        """List artifacts of a workflow run."""
        response = self.request("GET", f"/repos/{repo}/actions/runs/{run_id}/artifacts")
        artifacts = response.json().get("artifacts", [])
        return [a for a in artifacts if isinstance(a, dict)]

    def download_artifact(self, repo: str, artifact_id: str) -> bytes:
        """Download one artifact as bytes (zip archive)."""
        response = self.request(
            "GET",
            f"/repos/{repo}/actions/artifacts/{artifact_id}/zip",
            headers={"Accept": "application/vnd.github+json"},
        )
        return response.content

    def get_commit_sha(self, repo: str, branch: str) -> str:
        """Return the head sha of ``branch`` (alias kept for clarity at call sites)."""
        return self.get_branch_sha(repo, branch)

    def close(self) -> None:
        self._client.close()
