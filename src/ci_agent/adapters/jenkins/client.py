"""Jenkins REST API client for the Jenkins adapter (Batch 8, Task B).

Uses httpx directly against the Jenkins REST API — deliberately no Jenkins
SDK, per the vendor-neutrality discipline (Report Section 12). Same
timeout/error/no-logged-credential discipline as the GitHub/GitLab clients.

Auth: username + API token (``JENKINS_URL``, ``JENKINS_USER``,
``JENKINS_API_TOKEN`` environment variables, resolved by Settings). There is
NO default in non-local environments — constructing a client without the
full triple fails loudly (:class:`JenkinsAPIError`), and the token value is
never logged. Local dev uses the documented placeholders in ``.env.example``.

Note on CSRF: Jenkins classically requires a crumb for authenticated POSTs,
but requests authenticated with an API TOKEN are exempt from crumb checks on
supported Jenkins versions — the client therefore sends Basic auth only and
documents that assumption (NOTES.md).
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from ci_agent.adapters.errors import JenkinsAPIError
from ci_agent.reliability.retry_policies import retry_transient_external_call

DEFAULT_TIMEOUT_SECONDS = 10.0
_QUEUE_ITEM_LOCATION = re.compile(r"/queue/item/(\d+)/?")
# HTTP status Jenkins returns for "item already exists" on createItem.
JENKINS_ITEM_EXISTS_STATUS = 400

logger = logging.getLogger(__name__)


class JenkinsClient:
    """Thin Jenkins REST wrapper used by the adapter."""

    def __init__(
        self,
        base_url: str,
        username: str,
        api_token: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        if not (base_url and username and api_token):
            # Fail loud on construction: a half-configured client must never
            # exist silently (batch instruction; NOTES.md).
            raise JenkinsAPIError(
                "Jenkins is not fully configured (set JENKINS_URL, JENKINS_USER "
                "and JENKINS_API_TOKEN)"
            )
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._auth = httpx.BasicAuth(username, api_token)
        self._client = client or httpx.Client(
            base_url=self._base_url, timeout=timeout_seconds, auth=self._auth
        )
        logger.info("JenkinsClient initialised: jenkins auth: user=%s (token redacted)", username)

    # ---------------------------------------------------------- requests

    @retry_transient_external_call
    def request(
        self,
        method: str,
        path: str,
        *,
        content: str | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform an authenticated Jenkins request with explicit error mapping.

        Wrapped with ``retry_transient_external_call`` (same discipline as
        the other adapter clients): transport errors and 5xx responses are
        retried with bounded backoff; 4xx responses are NOT.
        """
        try:
            response = self._client.request(
                method, path, content=content, params=params, headers=headers
            )
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise JenkinsAPIError(f"Jenkins request {method} {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise JenkinsAPIError(
                f"Jenkins request {method} {path} returned HTTP {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )
        return response

    # ---------------------------------------------------- job lifecycle

    def create_job(self, name: str, config_xml: str) -> None:
        """Create job ``name`` from ``config_xml`` — or update it if it exists.

        Jenkins splits creation (``POST /createItem?name=``) from
        configuration update (``POST /job/<name>/config.xml``); a 400 from
        createItem means the job already exists, in which case the config is
        posted to the update endpoint. Create-or-update semantics keep
        re-dispatch of the same run id idempotent.
        """
        try:
            self.request(
                "POST",
                "/createItem",
                content=config_xml,
                params={"name": name},
                headers={"Content-Type": "application/xml"},
            )
        except JenkinsAPIError as exc:
            if exc.status_code != JENKINS_ITEM_EXISTS_STATUS:
                raise
            self.request(
                "POST",
                f"/job/{name}/config.xml",
                content=config_xml,
                headers={"Content-Type": "application/xml"},
            )

    def build_job(self, name: str, parameters: dict[str, str] | None = None) -> int:
        """Trigger a build of job ``name``; returns the queue item id.

        Parameterless jobs use ``POST /job/<name>/build``; parameterized jobs
        would use ``buildWithParameters`` (no parameters are compiled today —
        the argument exists for interface completeness and is validated).
        """
        if parameters:
            response = self.request("POST", f"/job/{name}/buildWithParameters", params=parameters)
        else:
            response = self.request("POST", f"/job/{name}/build")
        location = response.headers.get("Location", "")
        match = _QUEUE_ITEM_LOCATION.search(location)
        if not match:
            raise JenkinsAPIError(
                f"Jenkins build trigger for {name!r} returned no queue item "
                f"Location header (got {location!r})"
            )
        return int(match.group(1))

    def get_queue_item(self, queue_id: int) -> dict[str, Any]:
        """Fetch one queue item (``executable.number`` appears once it starts)."""
        response = self.request("GET", f"/queue/item/{queue_id}/api/json")
        return dict(response.json())

    # ---------------------------------------------------- build polling

    def get_build(self, name: str, build_number: str) -> dict[str, Any]:
        """Fetch one build object (``result`` is null while building)."""
        response = self.request("GET", f"/job/{name}/{build_number}/api/json")
        return dict(response.json())

    def get_build_log(self, name: str, build_number: str) -> str:
        """Fetch a build's console log (raw text)."""
        response = self.request("GET", f"/job/{name}/{build_number}/consoleText")
        return response.text

    def close(self) -> None:
        self._client.close()
