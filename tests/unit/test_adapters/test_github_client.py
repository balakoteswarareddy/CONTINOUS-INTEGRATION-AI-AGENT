"""Unit tests for the GitHub REST client (respx-mocked; Batch 4, Task A)."""

from __future__ import annotations

import httpx
import pytest
import respx

from ci_agent.adapters.github_actions.client import (
    GITHUB_API_BASE_URL,
    GitHubAPIError,
    GitHubAuthConfig,
    GitHubClient,
)

AUTH = GitHubAuthConfig(pat="test-pat-token")


@pytest.fixture()
def client() -> GitHubClient:
    return GitHubClient(AUTH)


@respx.mock
def test_pat_auth_header_sent(client: GitHubClient) -> None:
    route = respx.get(f"{GITHUB_API_BASE_URL}/repos/org/repo/git/ref/heads/main").mock(
        return_value=httpx.Response(200, json={"object": {"sha": "abc123"}})
    )

    sha = client.get_branch_sha("org/repo", "main")

    assert sha == "abc123"
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer test-pat-token"


@respx.mock
def test_create_branch_sends_ref_payload(client: GitHubClient) -> None:
    route = respx.post(f"{GITHUB_API_BASE_URL}/repos/org/repo/git/refs").mock(
        return_value=httpx.Response(201, json={"ref": "refs/heads/ci-agent/run-1"})
    )

    client.create_branch("org/repo", "ci-agent/run-1", "abc123")

    import json

    body = json.loads(route.calls.last.request.content)
    assert body == {"ref": "refs/heads/ci-agent/run-1", "sha": "abc123"}


@respx.mock
def test_create_file_base64_encodes_content(client: GitHubClient) -> None:
    respx.get(
        f"{GITHUB_API_BASE_URL}/repos/org/repo/contents/.github/workflows/wf.yml",
        params={"ref": "ci-agent/run-1"},
    ).mock(return_value=httpx.Response(404, text="not found"))
    workflow_path = f"{GITHUB_API_BASE_URL}/repos/org/repo/contents/.github/workflows/wf.yml"
    route = respx.put(workflow_path).mock(
        return_value=httpx.Response(201, json={"commit": {"sha": "deadbeef"}})
    )

    result = client.create_or_update_file(
        "org/repo",
        ".github/workflows/wf.yml",
        "on: workflow_dispatch\n",
        "ci-agent/run-1",
        "msg",
    )

    assert result["commit"]["sha"] == "deadbeef"
    import base64
    import json

    body = json.loads(route.calls.last.request.content)
    assert base64.b64decode(body["content"]).decode() == "on: workflow_dispatch\n"
    assert "sha" not in body  # new file: no sha


@respx.mock
def test_update_file_includes_existing_sha(client: GitHubClient) -> None:
    respx.get(f"{GITHUB_API_BASE_URL}/repos/org/repo/contents/wf.yml").mock(
        return_value=httpx.Response(200, json={"sha": "file-sha-1"})
    )
    route = respx.put(f"{GITHUB_API_BASE_URL}/repos/org/repo/contents/wf.yml").mock(
        return_value=httpx.Response(200, json={"commit": {"sha": "ok"}})
    )

    client.create_or_update_file("org/repo", "wf.yml", "new", "main", "update")

    import json

    body = json.loads(route.calls.last.request.content)
    assert body["sha"] == "file-sha-1"


@respx.mock
def test_trigger_workflow_dispatch(client: GitHubClient) -> None:
    route = respx.post(
        f"{GITHUB_API_BASE_URL}/repos/org/repo/actions/workflows/ci-agent-run.yml/dispatches"
    ).mock(return_value=httpx.Response(204))

    client.trigger_workflow_dispatch("org/repo", "ci-agent-run.yml", "ci-agent/run-1", {"k": "v"})

    import json

    assert route.called
    body = json.loads(route.calls.last.request.content)
    assert body == {"ref": "ci-agent/run-1", "inputs": {"k": "v"}}


@respx.mock
def test_get_workflow_run_and_check_runs(client: GitHubClient) -> None:
    respx.get(f"{GITHUB_API_BASE_URL}/repos/org/repo/actions/runs/42").mock(
        return_value=httpx.Response(
            200, json={"id": 42, "status": "completed", "conclusion": "success"}
        )
    )
    respx.get(f"{GITHUB_API_BASE_URL}/repos/org/repo/commits/ci-agent%2Frun-1/check-runs").mock(
        return_value=httpx.Response(
            200,
            json={
                "check_runs": [{"name": "checkout", "status": "completed", "conclusion": "success"}]
            },
        )
    )

    run = client.get_workflow_run("org/repo", "42")
    checks = client.get_check_runs("org/repo", "ci-agent/run-1")

    assert run["conclusion"] == "success"
    assert checks[0]["name"] == "checkout"


@respx.mock
def test_download_artifact_returns_bytes(client: GitHubClient) -> None:
    respx.get(f"{GITHUB_API_BASE_URL}/repos/org/repo/actions/artifacts/7/zip").mock(
        return_value=httpx.Response(200, content=b"PK-zip-bytes")
    )

    blob = client.download_artifact("org/repo", "7")

    assert blob == b"PK-zip-bytes"


@respx.mock
def test_post_check_run_payload(client: GitHubClient) -> None:
    route = respx.post(f"{GITHUB_API_BASE_URL}/repos/org/repo/check-runs").mock(
        return_value=httpx.Response(201, json={"id": 99})
    )

    client.post_check_run(
        "org/repo",
        "abc123",
        "ci-agent merge decision",
        status="completed",
        conclusion="success",
        output={"title": "approved", "summary": "see evidence"},
    )

    import json

    body = json.loads(route.calls.last.request.content)
    assert body["name"] == "ci-agent merge decision"
    assert body["conclusion"] == "success"


class TestErrorPaths:
    @respx.mock
    def test_401_raises_github_api_error_with_status(self, client: GitHubClient) -> None:
        respx.get(url__startswith=GITHUB_API_BASE_URL).mock(
            return_value=httpx.Response(401, text='{"message": "Bad credentials"}')
        )

        with pytest.raises(GitHubAPIError) as excinfo:
            client.get_workflow_run("org/repo", "1")

        assert excinfo.value.status_code == 401
        assert "Bad credentials" in (excinfo.value.body or "")

    @respx.mock
    def test_404_raises_github_api_error(self, client: GitHubClient) -> None:
        respx.get(url__startswith=GITHUB_API_BASE_URL).mock(
            return_value=httpx.Response(404, text="nope")
        )

        with pytest.raises(GitHubAPIError) as excinfo:
            client.get_workflow_run("org/repo", "404")

        assert excinfo.value.status_code == 404

    @respx.mock
    def test_timeout_raises_github_api_error(self, client: GitHubClient) -> None:
        respx.get(url__startswith=GITHUB_API_BASE_URL).mock(
            side_effect=httpx.ConnectTimeout("slow")
        )

        with pytest.raises(GitHubAPIError, match="slow"):
            client.get_workflow_run("org/repo", "1")

    @respx.mock
    def test_connection_error_raises_github_api_error(self, client: GitHubClient) -> None:
        respx.post(url__startswith=GITHUB_API_BASE_URL).mock(
            side_effect=httpx.ConnectError("refused")
        )

        with pytest.raises(GitHubAPIError, match="refused"):
            client.trigger_workflow_dispatch("org/repo", "wf.yml", "main")

    def test_500_raises_github_api_error(self) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(500, text="internal error"))
        client = GitHubClient(
            AUTH, client=httpx.Client(transport=transport, base_url=GITHUB_API_BASE_URL)
        )

        with pytest.raises(GitHubAPIError) as excinfo:
            client.get_workflow_run("org/repo", "1")

        assert excinfo.value.status_code == 500


class TestAppAuth:
    @respx.mock
    def test_app_jwt_exchange_fetches_installation_token(self, tmp_path) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key_path = tmp_path / "app-key.pem"
        key_path.write_bytes(pem)

        token_route = respx.post(
            f"{GITHUB_API_BASE_URL}/app/installations/1234/access_tokens"
        ).mock(
            return_value=httpx.Response(
                201, json={"token": "install-token-1", "expires_at": "soon"}
            )
        )
        data_route = respx.get(f"{GITHUB_API_BASE_URL}/repos/org/repo/actions/runs/9").mock(
            return_value=httpx.Response(200, json={"id": 9, "status": "queued"})
        )

        auth = GitHubAuthConfig(
            app_id="app-1", private_key_path=str(key_path), installation_id="1234"
        )

        client = GitHubClient(auth)

        run = client.get_workflow_run("org/repo", "9")

        assert run["status"] == "queued"
        # First call: JWT bearer on the token exchange, then installation token.
        exchange_auth = token_route.calls.last.request.headers["Authorization"]
        assert exchange_auth.startswith("Bearer ey")
        assert data_route.calls.last.request.headers["Authorization"] == "Bearer install-token-1"
        # Second call reuses the cached installation token (no new exchange).
        client.get_workflow_run("org/repo", "9")
        assert token_route.call_count == 1
        client.close()

    def test_missing_private_key_path_raises(self) -> None:
        auth = GitHubAuthConfig(app_id="a", installation_id="1")
        client = GitHubClient(auth)

        with pytest.raises(GitHubAPIError, match="private key"):
            client._auth_header()

    def test_redacted_description_never_leaks_secrets(self) -> None:
        pat_config = GitHubAuthConfig(pat="super-secret-value")
        assert "super-secret-value" not in pat_config.redacted_description()
        assert "redacted" in pat_config.redacted_description()
