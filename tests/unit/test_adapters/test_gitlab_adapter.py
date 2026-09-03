"""Unit tests: GitLab CI adapter + client (Batch 8, Task A).

Adapter flows use a hand-rolled fake client (existing project pattern);
client HTTP discipline is verified with respx-mocked transport.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx
import pytest
import respx
import yaml
from tests.unit.test_adapters.test_gitlab_compiler import build_plan

from ci_agent.adapters.errors import GitLabAPIError
from ci_agent.adapters.gitlab_ci.adapter import (
    GITLAB_STATUS_TO_STAGE_STATUS,
    GitLabCIAdapter,
    map_gitlab_status,
)
from ci_agent.adapters.gitlab_ci.client import GitLabClient
from ci_agent.core.models.common import StageStatus

PROJECT = "example-group/payments-api"


class _FakeGitLabClient:
    """Deterministic stand-in for the GitLab REST client."""

    def __init__(
        self,
        *,
        trigger_response: dict[str, Any] | None = None,
        pipeline: dict[str, Any] | None = None,
        jobs: list[dict[str, Any]] | None = None,
        pipelines_list: list[dict[str, Any]] | None = None,
    ) -> None:
        self.branches: list[tuple[str, str, str]] = []
        self.files: list[tuple[str, str, str, str]] = []
        self.triggers: list[tuple[str, str]] = []
        self.trigger_response = trigger_response
        self.pipeline = pipeline or {"id": 42, "status": "success", "ref": "ci-agent/run-1"}
        self.jobs = jobs or []
        self.pipelines_list = pipelines_list or []

    def create_branch(self, project_id: str, branch: str, ref: str) -> dict[str, Any]:
        self.branches.append((project_id, branch, ref))
        return {"name": branch}

    def create_or_update_file(
        self, project_id: str, file_path: str, content: str, branch: str, commit_message: str
    ) -> dict[str, Any]:
        self.files.append((project_id, file_path, branch, commit_message))
        return {"file_path": file_path}

    def trigger_pipeline(
        self, project_id: str, ref: str, variables: dict[str, str] | None = None
    ) -> dict[str, Any]:
        self.triggers.append((project_id, ref))
        return self.trigger_response if self.trigger_response is not None else {"id": 42}

    def get_pipeline(self, project_id: str, pipeline_id: str) -> dict[str, Any]:
        return self.pipeline

    def get_pipeline_jobs(self, project_id: str, pipeline_id: str) -> list[dict[str, Any]]:
        return self.jobs

    def list_pipelines(self, project_id: str, ref: str, per_page: int = 10) -> list[dict[str, Any]]:
        return self.pipelines_list

    def get_job_log(self, project_id: str, job_id: str) -> str:
        return f"log of job {job_id}"

    def post_commit_status(
        self, project_id: str, sha: str, state: str, name: str, description: str
    ) -> dict[str, Any]:
        return {"sha": sha, "state": state}


def _metadata() -> dict[str, str]:
    return {"repository": PROJECT, "source_sha": "abc123def456"}


class TestCompile:
    def test_compile_wraps_gitlab_yaml_with_correct_kind_and_hash(self) -> None:
        adapter = GitLabCIAdapter(_FakeGitLabClient())
        artifact = adapter.compile(build_plan(), metadata=_metadata())

        assert artifact.kind == "gitlab_ci_pipeline"
        expected = hashlib.sha256(artifact.content.encode("utf-8")).hexdigest()
        assert artifact.content_hash == f"sha256:{expected}"
        # The content is parseable YAML with the expected skeleton.
        parsed = yaml.safe_load(artifact.content)
        assert "stages" in parsed
        assert "ci-agent-results" in parsed
        assert artifact.metadata["repository"] == PROJECT
        assert artifact.metadata["file_path"] == ".gitlab-ci.yml"

    def test_compile_requires_repository_and_source_sha(self) -> None:
        adapter = GitLabCIAdapter(_FakeGitLabClient())
        with pytest.raises(ValueError, match="repository"):
            adapter.compile(build_plan(), metadata={"source_sha": "abc"})
        with pytest.raises(ValueError, match="source_sha"):
            adapter.compile(build_plan(), metadata={"repository": PROJECT})


class TestDispatch:
    def test_dispatch_pushes_file_and_triggers_on_ci_agent_branch(self) -> None:
        client = _FakeGitLabClient()
        adapter = GitLabCIAdapter(client)
        artifact = adapter.compile(build_plan(), metadata=_metadata())

        ref = adapter.dispatch(artifact, "run-1")

        assert ref.run_id == "run-1"
        assert ref.branch == "ci-agent/run-1"
        assert ref.repository == PROJECT
        # Branch created from the source sha, file committed, then triggered.
        assert client.branches == [(PROJECT, "ci-agent/run-1", "abc123def456")]
        assert client.files[0][1] == ".gitlab-ci.yml"
        assert client.files[0][2] == "ci-agent/run-1"
        assert client.triggers == [(PROJECT, "ci-agent/run-1")]
        # Pipeline id resolved from the trigger response.
        assert ref.external_run_id == "42"
        assert ref.workflow_ref == ".gitlab-ci.yml"

    def test_dispatch_resolves_pipeline_id_via_bounded_retry_fallback(self) -> None:
        """When the trigger response carries no id, the bounded retry over
        the branch's pipeline list resolves it (GitHub-style pattern)."""
        client = _FakeGitLabClient(
            trigger_response={},  # no id in the response
            pipelines_list=[{"ref": "ci-agent/run-2", "id": 77}],
        )
        adapter = GitLabCIAdapter(client, pipeline_id_resolution_backoff_seconds=0.0)
        artifact = adapter.compile(build_plan(), metadata=_metadata())

        ref = adapter.dispatch(artifact, "run-2")
        assert ref.external_run_id == "77"

    def test_dispatch_returns_none_when_never_resolved(self) -> None:
        client = _FakeGitLabClient(trigger_response={}, pipelines_list=[])
        adapter = GitLabCIAdapter(client, pipeline_id_resolution_backoff_seconds=0.0)
        artifact = adapter.compile(build_plan(), metadata=_metadata())

        ref = adapter.dispatch(artifact, "run-3")
        assert ref.external_run_id is None  # recorded, not fatal


class TestPollStatus:
    def _ref(self) -> Any:
        from ci_agent.adapters.base import DispatchRef

        return DispatchRef(
            run_id="run-1",
            repository=PROJECT,
            branch="ci-agent/run-1",
            external_run_id="42",
        )

    def test_poll_maps_pipeline_and_job_statuses(self) -> None:
        client = _FakeGitLabClient(
            pipeline={"id": 42, "status": "running", "ref": "ci-agent/run-1"},
            jobs=[
                {"name": "format_lint", "status": "success", "id": 101},
                {"name": "sast", "status": "failed", "id": 102},
                {"name": "ci-agent-results", "status": "created", "id": 103},
            ],
        )
        snapshot = GitLabCIAdapter(client).poll_status(self._ref())

        assert snapshot.run_id == "run-1"
        assert snapshot.status is StageStatus.RUNNING
        assert snapshot.completed is False
        # The summary job is skipped; stages carry the explicit mapping.
        assert [(s.stage_id, s.status) for s in snapshot.stages] == [
            ("format_lint", StageStatus.PASSED),
            ("sast", StageStatus.FAILED),
        ]

    def test_poll_completed_pipeline(self) -> None:
        client = _FakeGitLabClient(pipeline={"id": 42, "status": "success"})
        snapshot = GitLabCIAdapter(client).poll_status(self._ref())
        assert snapshot.status is StageStatus.PASSED
        assert snapshot.completed is True

    def test_poll_requires_external_run_id(self) -> None:
        from ci_agent.adapters.base import DispatchRef

        ref = DispatchRef(run_id="run-1", repository=PROJECT, branch="ci-agent/run-1")
        with pytest.raises(ValueError, match="external_run_id"):
            GitLabCIAdapter(_FakeGitLabClient()).poll_status(ref)


class TestFetchStepLogs:
    def test_fetches_the_named_jobs_trace(self) -> None:
        client = _FakeGitLabClient(jobs=[{"name": "sast", "status": "success", "id": 102}])
        adapter = GitLabCIAdapter(client)
        from ci_agent.adapters.base import DispatchRef

        ref = DispatchRef(
            run_id="run-1",
            repository=PROJECT,
            branch="ci-agent/run-1",
            external_run_id="42",
        )
        assert adapter.fetch_step_logs(ref, "sast") == "log of job 102"

    def test_unknown_step_raises(self) -> None:
        adapter = GitLabCIAdapter(_FakeGitLabClient(jobs=[]))
        from ci_agent.adapters.base import DispatchRef

        ref = DispatchRef(
            run_id="run-1",
            repository=PROJECT,
            branch="ci-agent/run-1",
            external_run_id="42",
        )
        with pytest.raises(GitLabAPIError, match="not found"):
            adapter.fetch_step_logs(ref, "nope")


class TestStatusMappingTable:
    @pytest.mark.parametrize(
        ("gitlab_status", "expected"),
        [
            ("created", StageStatus.PENDING),
            ("pending", StageStatus.PENDING),
            ("running", StageStatus.RUNNING),
            ("success", StageStatus.PASSED),
            ("failed", StageStatus.FAILED),
            ("canceled", StageStatus.CANCELLED),
            ("skipped", StageStatus.SKIPPED),
        ],
    )
    def test_explicit_mapping(self, gitlab_status: str, expected: StageStatus) -> None:
        assert map_gitlab_status(gitlab_status) is expected
        assert GITLAB_STATUS_TO_STAGE_STATUS[gitlab_status] is expected

    @pytest.mark.parametrize("unknown", ["", "manual", "waiting_for_resource", "SUCCESS"])
    def test_unknown_status_fails_closed_to_failed(self, unknown: str) -> None:
        assert map_gitlab_status(unknown) is StageStatus.FAILED


class TestGitLabClientHttp:
    """respx-mocked transport: auth header, error mapping, endpoints."""

    @respx.mock
    def test_requests_carry_private_token_header(self) -> None:
        route = respx.get("https://gitlab.example/api/v4/projects/x").respond(json={"ok": True})
        client = GitLabClient("tok-123", base_url="https://gitlab.example/api/v4")
        response = client.request("GET", "/projects/x")
        assert response.json() == {"ok": True}
        request = route.calls[0].request
        assert request.headers["PRIVATE-TOKEN"] == "tok-123"

    @respx.mock
    def test_http_error_raises_gitlab_api_error_with_status(self) -> None:
        respx.get("https://gitlab.example/api/v4/projects/x").respond(404, json={"message": "no"})
        client = GitLabClient("tok", base_url="https://gitlab.example/api/v4")
        with pytest.raises(GitLabAPIError) as excinfo:
            client.request("GET", "/projects/x")
        assert excinfo.value.status_code == 404

    @respx.mock
    def test_transport_error_raises_gitlab_api_error(self) -> None:
        respx.get("https://gitlab.example/api/v4/projects/x").mock(
            side_effect=httpx.ConnectError("boom")
        )
        client = GitLabClient("tok", base_url="https://gitlab.example/api/v4")
        with pytest.raises(GitLabAPIError) as excinfo:
            client.request("GET", "/projects/x")
        assert excinfo.value.status_code is None

    def test_construction_without_token_fails_loud(self) -> None:
        with pytest.raises(GitLabAPIError, match="GITLAB_ACCESS_TOKEN"):
            GitLabClient("")

    @respx.mock
    def test_trigger_pipeline_posts_ref_and_variables(self) -> None:
        route = respx.post("https://gitlab.example/api/v4/projects/g%2Fr/pipeline").respond(
            201, json={"id": 9, "status": "created"}
        )
        client = GitLabClient("tok", base_url="https://gitlab.example/api/v4")
        pipeline = client.trigger_pipeline("g/r", "ci-agent/run-1", {"k": "v"})
        assert pipeline["id"] == 9
        import json as _json

        body = _json.loads(route.calls[0].request.content)
        assert body == {"ref": "ci-agent/run-1", "variables": {"k": "v"}}

    @respx.mock
    def test_create_or_update_file_falls_back_to_put_on_conflict(self) -> None:
        project = "g%2Fr"
        respx.post(
            f"https://gitlab.example/api/v4/projects/{project}/repository/files/.gitlab-ci.yml"
        ).respond(400, json={"message": "already exists"})
        put = respx.put(
            f"https://gitlab.example/api/v4/projects/{project}/repository/files/.gitlab-ci.yml"
        ).respond(200, json={"file_path": ".gitlab-ci.yml"})
        client = GitLabClient("tok", base_url="https://gitlab.example/api/v4")
        result = client.create_or_update_file(
            "g/r", ".gitlab-ci.yml", "content", "ci-agent/run-1", "msg"
        )
        assert result["file_path"] == ".gitlab-ci.yml"
        assert put.called

    @respx.mock
    def test_get_job_log_returns_trace_text(self) -> None:
        respx.get("https://gitlab.example/api/v4/projects/g%2Fr/jobs/7/trace").respond(
            200, text="hello trace"
        )
        client = GitLabClient("tok", base_url="https://gitlab.example/api/v4")
        assert client.get_job_log("g/r", "7") == "hello trace"
