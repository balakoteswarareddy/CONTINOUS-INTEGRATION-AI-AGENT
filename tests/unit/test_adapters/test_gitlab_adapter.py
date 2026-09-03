"""GitLab client (respx) + adapter (fake-client) tests (Batch 8, Task B)."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

import httpx
import pytest
import respx
import yaml

from ci_agent.adapters.gitlab_ci.adapter import GitLabCIAdapter, map_gitlab_status
from ci_agent.adapters.gitlab_ci.client import GitLabAPIError, GitLabClient
from ci_agent.adapters.gitlab_ci.compiler import compile_to_gitlab_ci
from ci_agent.core.models.common import StageStatus

BASE = "https://gitlab.example.com"
PROJECT = "42"
API = f"{BASE}/api/v4/projects/{PROJECT}"


class TestGitLabClient:
    @respx.mock
    def test_branch_sha_and_pipeline_creation(self) -> None:
        respx.get(f"{API}/repository/branches/ci-agent/run-1").mock(
            return_value=httpx.Response(200, json={"commit": {"id": "abc123"}})
        )
        respx.post(f"{API}/pipeline").mock(return_value=httpx.Response(201, json={"id": 9001}))
        client = GitLabClient(BASE, "glpat-test", PROJECT)
        try:
            assert client.get_branch_sha("ci-agent/run-1") == "abc123"
            assert client.create_pipeline("ci-agent/run-1") == "9001"
        finally:
            client.close()

    @respx.mock
    def test_token_travels_in_private_token_header(self) -> None:
        route = respx.get(f"{API}/pipelines/9001").mock(
            return_value=httpx.Response(200, json={"id": 9001, "status": "running"})
        )
        client = GitLabClient(BASE, "glpat-super-secret", PROJECT)
        try:
            client.get_pipeline("9001")
        finally:
            client.close()
        sent = route.calls.last.request.headers["PRIVATE-TOKEN"]
        assert sent == "glpat-super-secret"

    @respx.mock
    def test_client_error_is_typed_not_retried(self) -> None:
        respx.post(f"{API}/repository/branches").mock(
            return_value=httpx.Response(400, json={"message": "bad branch"})
        )
        client = GitLabClient(BASE, "glpat-test", PROJECT)
        try:
            with pytest.raises(GitLabAPIError) as excinfo:
                client.create_branch("bad branch", "main")
            assert excinfo.value.status_code == 400
        finally:
            client.close()

    @respx.mock
    def test_token_never_in_error_messages(self) -> None:
        respx.get(f"{API}/pipelines/9001").mock(return_value=httpx.Response(500, text="boom"))
        client = GitLabClient(BASE, "glpat-super-secret", PROJECT)
        try:
            with pytest.raises(GitLabAPIError) as excinfo:
                client.get_pipeline("9001")
            assert "glpat-super-secret" not in str(excinfo.value)
        finally:
            client.close()


class _FakeGitLabClient:
    """Scripted client for adapter tests (unit only)."""

    def __init__(self) -> None:
        self.branches: list[tuple[str, str]] = []
        self.commits: list[dict[str, Any]] = []
        self.pipelines: list[str] = []
        self.jobs: list[dict[str, Any]] = []
        self.artifacts: dict[str, bytes] = {}
        self.traces: dict[str, str] = {}

    def create_branch(self, branch: str, ref: str) -> None:
        self.branches.append((branch, ref))

    def commit_files(self, branch: str, files: dict[str, str], *, commit_message: str) -> str:
        self.commits.append({"branch": branch, "files": files, "message": commit_message})
        return "commitabc"

    def create_pipeline(self, branch: str) -> str:
        self.pipelines.append(branch)
        return "9001"

    def get_pipeline(self, pipeline_id: str) -> dict[str, Any]:
        return {"id": int(pipeline_id), "status": "running"}

    def list_pipeline_jobs(self, pipeline_id: str) -> list[dict[str, Any]]:
        return list(self.jobs)

    def get_job_trace(self, job_id: str) -> str:
        return self.traces.get(job_id, "")

    def download_job_artifacts(self, job_id: str) -> bytes:
        return self.artifacts.get(job_id, b"")


class TestGitLabAdapter:
    def _adapter(self) -> tuple[GitLabCIAdapter, _FakeGitLabClient]:
        client = _FakeGitLabClient()
        return GitLabCIAdapter(client), client  # type: ignore[arg-type]

    def test_compile_and_dispatch_shape(self) -> None:
        from tests.unit.test_adapters.test_compiler import build_plan

        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        assert artifact.kind == "gitlab_ci_pipeline"
        assert artifact.content_hash.startswith("sha256:")
        assert artifact.metadata["pipeline_path"] == ".gitlab-ci.yml"

        ref = adapter.dispatch(artifact, "run-gl-1")
        assert client.branches == [("ci-agent/run-gl-1", "abc")]
        assert ref.external_run_id == "9001"
        assert ref.branch == "ci-agent/run-gl-1"
        committed = client.commits[0]
        assert ".gitlab-ci.yml" in committed["files"]

    def test_compile_requires_metadata(self) -> None:
        from tests.unit.test_adapters.test_compiler import build_plan

        adapter, _ = self._adapter()
        with pytest.raises(ValueError, match="missing required keys"):
            adapter.compile(build_plan(), {})

    def test_poll_status_maps_jobs_fail_closed(self) -> None:
        from tests.unit.test_adapters.test_compiler import build_plan

        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-gl-2")
        client.jobs = [
            {"name": "stage-sast", "status": "success"},
            {"name": "stage-unit_tests", "status": "running"},
            {"name": "some-other-job", "status": "running"},
            {"name": "stage-dependency_scan", "status": "weird-new-status"},
        ]
        snapshot = adapter.poll_status(ref)
        by_stage = {s.stage_id: s for s in snapshot.stages}
        assert by_stage["sast"].status is StageStatus.PASSED
        assert by_stage["unit_tests"].status is StageStatus.RUNNING
        # Unknown status -> FAILED (fail-closed), other jobs not correlated.
        assert by_stage["dependency_scan"].status is StageStatus.FAILED
        assert len(snapshot.stages) == 3

    def test_status_mapping_table_is_fail_closed(self) -> None:
        assert map_gitlab_status("success") is StageStatus.PASSED
        assert map_gitlab_status("failed") is StageStatus.FAILED
        assert map_gitlab_status("canceled") is StageStatus.CANCELLED
        assert map_gitlab_status("brand-new-status") is StageStatus.FAILED

    def test_fetch_step_logs_targets_job_trace(self) -> None:
        from tests.unit.test_adapters.test_compiler import build_plan

        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-gl-3")
        client.jobs = [{"name": "stage-sast", "status": "success", "id": 77}]
        client.traces["77"] = "bandit output line 1"
        assert adapter.fetch_step_logs(ref, "sast") == "bandit output line 1"

    def test_download_stage_scan_artifact_extracts_json(self) -> None:
        from tests.unit.test_adapters.test_compiler import build_plan

        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-gl-4")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("bandit-report.json", json.dumps({"results": []}))
            archive.writestr("notes.txt", "ignored")
        client.jobs = [{"name": "stage-sast", "status": "success", "id": 88}]
        client.artifacts["88"] = buffer.getvalue()
        contents = adapter.download_stage_scan_artifact(ref, "sast")
        assert contents == {"bandit-report.json": json.dumps({"results": []})}

    def test_download_absent_artifact_returns_empty(self) -> None:
        from tests.unit.test_adapters.test_compiler import build_plan

        adapter, _ = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-gl-5")
        assert adapter.download_stage_scan_artifact(ref, "sast") == {}


def test_compiled_pipeline_is_valid_yaml() -> None:
    from tests.unit.test_adapters.test_compiler import build_phase_b_plan

    text = compile_to_gitlab_ci(build_phase_b_plan())
    payload = yaml.safe_load(text)
    assert "stage-record_evidence" in payload
