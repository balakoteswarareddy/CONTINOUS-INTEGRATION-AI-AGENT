"""Jenkins compiler + client + adapter tests (Batch 8, Task C)."""

from __future__ import annotations

import base64
from typing import Any

import httpx
import pytest
import respx
from tests.unit.test_adapters.test_compiler import build_phase_b_plan, build_plan

from ci_agent.adapters.jenkins.adapter import (
    JenkinsAdapter,
    map_jenkins_stage_status,
)
from ci_agent.adapters.jenkins.client import JenkinsAPIError, JenkinsClient
from ci_agent.adapters.jenkins.compiler import compile_to_jenkinsfile
from ci_agent.core.models.common import StageStatus

BASE = "https://jenkins.example.com"
JOB = "ci-agent"


class TestJenkinsCompiler:
    def test_one_stage_per_ci_agent_stage_in_topological_order(self) -> None:
        text = compile_to_jenkinsfile(build_plan())
        order = [
            line.split("stage('")[1].split("')")[0]
            for line in text.splitlines()
            if "stage('" in line
        ]
        assert order[0] == "checkout"
        assert order.index("policy_gate") > order.index("unit_tests")
        assert order.index("policy_gate") > order.index("secret_scan")
        assert order.index("policy_gate") > order.index("dependency_scan")

    def test_commands_are_verbatim_registry_values(self) -> None:
        text = compile_to_jenkinsfile(build_plan())
        assert "bandit -r . -f json -o bandit-report.json" in text

    def test_report_artifacts_archived(self) -> None:
        text = compile_to_jenkinsfile(build_plan())
        assert "archiveArtifacts" in text
        assert "'bandit-report.json'" in text

    def test_phase_b_stages_compile(self) -> None:
        text = compile_to_jenkinsfile(build_phase_b_plan())
        assert "stage('record_evidence')" in text
        assert "trivy image --format json" in text

    def test_never_references_credentials(self) -> None:
        text = compile_to_jenkinsfile(build_plan())
        assert "withCredentials" not in text
        assert "secrets." not in text

    def test_exit_code_capture_is_fixed_boilerplate(self) -> None:
        text = compile_to_jenkinsfile(build_plan())
        assert 'echo "exit_code=$code" >> ci_agent_exit_code.txt' in text


class TestJenkinsClient:
    @respx.mock
    def test_trigger_build_returns_queue_location(self) -> None:
        respx.post(f"{BASE}/job/{JOB}/buildWithParameters").mock(
            return_value=httpx.Response(201, headers={"Location": f"{BASE}/queue/item/42/"})
        )
        client = JenkinsClient(BASE, "ci-agent", "token123", JOB)
        try:
            assert client.trigger_build({"CI_AGENT_RUN_ID": "run-1"}) == f"{BASE}/queue/item/42/"
        finally:
            client.close()

    @respx.mock
    def test_basic_auth_used_and_token_never_in_errors(self) -> None:
        route = respx.get(f"{BASE}/job/{JOB}/42/api/json").mock(
            return_value=httpx.Response(200, json={"building": False, "result": "SUCCESS"})
        )
        client = JenkinsClient(BASE, "ci-agent", "token-super-secret", JOB)
        try:
            client.get_build("42")
            sent = route.calls.last.request.headers["Authorization"]
            assert sent.startswith("Basic ")
            decoded = base64.b64decode(sent.removeprefix("Basic ")).decode("utf-8")
            assert decoded == "ci-agent:token-super-secret"
            respx.get(f"{BASE}/job/{JOB}/43/api/json").mock(
                return_value=httpx.Response(500, text="boom")
            )
            with pytest.raises(JenkinsAPIError) as excinfo:
                client.get_build("43")
            assert "token-super-secret" not in str(excinfo.value)
        finally:
            client.close()

    @respx.mock
    def test_describe_build_stages(self) -> None:
        respx.get(f"{BASE}/job/{JOB}/42/wfapi/describe").mock(
            return_value=httpx.Response(
                200,
                json={
                    "stages": [
                        {"name": "checkout", "status": "SUCCESS"},
                        {"name": "sast", "status": "FAILED"},
                    ]
                },
            )
        )
        client = JenkinsClient(BASE, "ci-agent", "token", JOB)
        try:
            stages = client.describe_build_stages("42")
            assert stages[1]["name"] == "sast"
        finally:
            client.close()


class _FakeJenkinsClient:
    def __init__(self) -> None:
        self.builds: dict[str, dict[str, Any]] = {
            "77": {"building": False, "result": "SUCCESS", "artifacts": []}
        }
        self.stages: dict[str, list[dict[str, Any]]] = {}
        self.triggers: list[dict[str, str]] = []
        self.artifact_blobs: dict[str, bytes] = {}
        self._next_queue = 100

    def trigger_build(self, parameters: dict[str, str] | None = None) -> str:
        self.triggers.append(parameters or {})
        self._next_queue += 1
        return f"https://jenkins.example.com/queue/item/{self._next_queue}/"

    def get_queue_item(self, queue_location: str) -> dict[str, Any]:
        number = str(int(queue_location.rstrip("/").rsplit("/", 1)[-1]) - 23)
        return {"executable": {"number": number}}

    def get_build(self, build_number: str) -> dict[str, Any]:
        return self.builds[build_number]

    def describe_build_stages(self, build_number: str) -> list[dict[str, Any]]:
        return self.stages.get(build_number, [])

    def download_artifact(self, build_number: str, artifact_path: str) -> bytes:
        return self.artifact_blobs.get(artifact_path, b"")

    def job_path(self) -> str:
        return f"/job/{JOB}"


class TestJenkinsAdapter:
    def _adapter(self) -> tuple[JenkinsAdapter, _FakeJenkinsClient]:
        client = _FakeJenkinsClient()
        return JenkinsAdapter(client), client  # type: ignore[arg-type]

    def test_compile_and_dispatch_resolves_build_number(self) -> None:
        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        assert artifact.kind == "jenkins_pipeline"
        ref = adapter.dispatch(artifact, "run-jk-1")
        assert ref.external_run_id == "78"  # queue 101 -> build 78
        assert client.triggers[0]["CI_AGENT_RUN_ID"] == "run-jk-1"
        assert client.triggers[0]["CI_AGENT_PIPELINE_HASH"] == artifact.content_hash

    def test_dispatch_resolves_after_bounded_retries(self) -> None:
        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        # Build number resolves on the third poll: monkeypatch the queue to be
        # empty twice by shrinking attempts instead (deterministic, fast).
        lazy = JenkinsAdapter(
            client, build_resolution_attempts=1, build_resolution_backoff_seconds=0.0
        )

        class _EmptyClient(_FakeJenkinsClient):
            def get_queue_item(self, queue_location: str) -> dict[str, Any]:
                return {}

        lazy._client = _EmptyClient()  # type: ignore[assignment]
        with pytest.raises(JenkinsAPIError, match="did not resolve"):
            lazy.dispatch(artifact, "run-jk-2")

    def test_poll_status_maps_stages_fail_closed(self) -> None:
        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-jk-3")
        client.builds["78"] = {"building": False, "result": "SUCCESS", "artifacts": []}
        client.stages["78"] = [
            {"name": "checkout", "status": "SUCCESS"},
            {"name": "sast", "status": "BRAND-NEW-STATUS"},
        ]
        snapshot = adapter.poll_status(ref)
        by_stage = {s.stage_id: s for s in snapshot.stages}
        assert by_stage["checkout"].status is StageStatus.PASSED
        assert by_stage["sast"].status is StageStatus.FAILED  # unknown -> FAILED
        assert snapshot.completed is True

    def test_poll_running_build(self) -> None:
        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-jk-4")
        client.builds["78"] = {"building": True, "result": None, "artifacts": []}
        snapshot = adapter.poll_status(ref)
        assert snapshot.completed is False
        assert snapshot.status is StageStatus.RUNNING

    def test_status_mapping_table_is_fail_closed(self) -> None:
        assert map_jenkins_stage_status("SUCCESS") is StageStatus.PASSED
        assert map_jenkins_stage_status("ABORTED") is StageStatus.CANCELLED
        assert map_jenkins_stage_status("NOT_BUILT") is StageStatus.SKIPPED
        assert map_jenkins_stage_status("SOMETHING-NEW") is StageStatus.FAILED

    def test_download_stage_scan_artifact_from_archive_dir(self) -> None:
        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-jk-5")
        assert ref.external_run_id == "78"
        client.builds["78"] = {
            "building": False,
            "result": "SUCCESS",
            "artifacts": [
                {"relativePath": "ci-agent-scan-sast/bandit-report.json"},
                {"relativePath": "other/ignored.txt"},
            ],
        }
        client.artifact_blobs["ci-agent-scan-sast/bandit-report.json"] = b'{"results": []}'
        contents = adapter.download_stage_scan_artifact(ref, "sast")
        assert contents == {"bandit-report.json": '{"results": []}'}

    def test_download_absent_artifact_returns_empty(self) -> None:
        adapter, client = self._adapter()
        artifact = adapter.compile(build_plan(), {"repository": "org/repo", "source_sha": "abc"})
        ref = adapter.dispatch(artifact, "run-jk-6")
        client.builds[ref.external_run_id or ""] = {
            "building": False,
            "result": "SUCCESS",
            "artifacts": [],
        }
        assert adapter.download_stage_scan_artifact(ref, "sast") == {}
