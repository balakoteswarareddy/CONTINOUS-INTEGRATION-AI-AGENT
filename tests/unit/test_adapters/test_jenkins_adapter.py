"""Unit tests: Jenkins adapter + client (Batch 8, Task B).

Adapter flows use a hand-rolled fake client; client HTTP discipline is
verified with respx-mocked transport.
"""

from __future__ import annotations

import hashlib
from typing import Any
from xml.etree import ElementTree

import httpx
import pytest
import respx
from tests.unit.test_adapters.test_gitlab_compiler import build_plan

from ci_agent.adapters.base import DispatchRef
from ci_agent.adapters.errors import JenkinsAPIError
from ci_agent.adapters.jenkins.adapter import (
    JENKINS_RESULT_TO_STAGE_STATUS,
    JenkinsAdapter,
    build_job_config_xml,
    job_name_for_run,
    map_jenkins_result,
)
from ci_agent.adapters.jenkins.client import JenkinsClient
from ci_agent.core.models.common import StageStatus

JENKINS_BASE = "https://jenkins.example"


class _FakeJenkinsClient:
    """Deterministic stand-in for the Jenkins REST client."""

    def __init__(
        self,
        *,
        queue_executable: dict[str, Any] | None = None,
        build: dict[str, Any] | None = None,
    ) -> None:
        self.jobs: list[tuple[str, str]] = []
        self.builds: list[str] = []
        self.queue_polls = 0
        self.queue_executable = queue_executable
        self.build = build or {"result": "SUCCESS", "building": False, "number": 5}

    def create_job(self, name: str, config_xml: str) -> None:
        self.jobs.append((name, config_xml))

    def build_job(self, name: str, parameters: dict[str, str] | None = None) -> int:
        self.builds.append(name)
        return 77

    def get_queue_item(self, queue_id: int) -> dict[str, Any]:
        self.queue_polls += 1
        return (
            self.queue_executable
            if self.queue_executable is not None
            else {
                "id": queue_id,
                "executable": {"number": 5},
            }
        )

    def get_build(self, name: str, build_number: str) -> dict[str, Any]:
        return self.build

    def get_build_log(self, name: str, build_number: str) -> str:
        return f"console of {name} #{build_number}"


def _metadata() -> dict[str, str]:
    return {"repository": "example-org/payments-api", "source_sha": "abc123"}


class TestCompile:
    def test_compile_wraps_declarative_jenkinsfile_with_correct_kind_and_hash(self) -> None:
        adapter = JenkinsAdapter(_FakeJenkinsClient())
        artifact = adapter.compile(build_plan(), metadata=_metadata())

        assert artifact.kind == "jenkins_declarative_pipeline"
        expected = hashlib.sha256(artifact.content.encode("utf-8")).hexdigest()
        assert artifact.content_hash == f"sha256:{expected}"
        assert artifact.content.startswith("// ci-agent compiled pipeline")
        assert "pipeline {" in artifact.content
        assert "agent any" in artifact.content
        assert artifact.metadata["repository"] == "example-org/payments-api"

    def test_no_results_artifact_step_in_jenkinsfile(self) -> None:
        """Poll-based result collection: no ci-agent-results job is compiled."""
        adapter = JenkinsAdapter(_FakeJenkinsClient())
        artifact = adapter.compile(build_plan(), metadata=_metadata())
        assert "ci-agent-results" not in artifact.content
        assert "result.json" not in artifact.content

    def test_single_quotes_in_commands_are_escaped(self) -> None:
        """The container.build command embeds '{{.Id}}' single quotes — the
        Groovy sh string must survive them."""
        from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep

        plan = ExecutionPlan(
            run_id="run-q",
            pipeline_spec_ref="sha256:abc",
            resolved_steps=[
                ResolvedStep(
                    step_id="container_build.docker",
                    stage_id="container_build",
                    tool_name="docker",
                    tool_version="27.3.1",
                    container_image="docker:27.3.1-cli",
                    command_template_id="container.build",
                    timeout_seconds=600,
                    depends_on=[],
                )
            ],
        )
        adapter = JenkinsAdapter(_FakeJenkinsClient())
        artifact = adapter.compile(plan, metadata=_metadata())
        assert "docker inspect" in artifact.content
        assert "\\'{{.Id}}\\'" in artifact.content

    def test_compile_requires_repository_and_source_sha(self) -> None:
        adapter = JenkinsAdapter(_FakeJenkinsClient())
        with pytest.raises(ValueError, match="repository"):
            adapter.compile(build_plan(), metadata={})


class TestDispatch:
    def test_dispatch_creates_job_triggers_build_and_resolves_number(self) -> None:
        client = _FakeJenkinsClient()
        adapter = JenkinsAdapter(client, build_number_resolution_backoff_seconds=0.0)
        artifact = adapter.compile(build_plan(), metadata=_metadata())

        ref = adapter.dispatch(artifact, "run-1")

        assert ref.run_id == "run-1"
        assert ref.repository == "ci-agent-run-1"  # the job name
        assert ref.branch == "ci-agent/run-1"  # dispatch label convention
        assert ref.external_run_id == "5"  # from queue-item polling
        # The job was created with a config XML embedding the Jenkinsfile.
        job_name, config_xml = client.jobs[0]
        assert job_name == "ci-agent-run-1"
        assert "pipeline {" in config_xml
        assert "<script>" in config_xml
        assert client.builds == ["ci-agent-run-1"]

    def test_dispatch_returns_none_when_queue_never_resolves(self) -> None:
        client = _FakeJenkinsClient(queue_executable={"id": 77})  # no executable
        adapter = JenkinsAdapter(client, build_number_resolution_backoff_seconds=0.0)
        artifact = adapter.compile(build_plan(), metadata=_metadata())
        ref = adapter.dispatch(artifact, "run-2")
        assert ref.external_run_id is None
        assert client.queue_polls == 5  # bounded retry: exactly 5 attempts

    def test_config_xml_is_parseable_and_sandboxed(self) -> None:
        config = build_job_config_xml("pipeline {\n}\n", "run-3")
        root = ElementTree.fromstring(config)
        assert root.tag == "flow-definition"
        assert root.find(".//sandbox").text == "true"
        assert "run-3" in (root.find("description").text or "")


class TestPollStatus:
    def _ref(self) -> DispatchRef:
        return DispatchRef(
            run_id="run-1",
            repository="ci-agent-run-1",
            branch="ci-agent/run-1",
            external_run_id="5",
        )

    def test_poll_maps_terminal_build(self) -> None:
        client = _FakeJenkinsClient(build={"result": "SUCCESS", "building": False})
        snapshot = JenkinsAdapter(client).poll_status(self._ref())
        assert snapshot.run_id == "run-1"
        assert snapshot.status is StageStatus.PASSED
        assert snapshot.completed is True
        assert snapshot.stages == []  # run-level polling for MVP (documented)

    def test_poll_in_progress_build_maps_to_running(self) -> None:
        client = _FakeJenkinsClient(build={"result": None, "building": True})
        snapshot = JenkinsAdapter(client).poll_status(self._ref())
        assert snapshot.status is StageStatus.RUNNING
        assert snapshot.completed is False

    def test_poll_requires_external_run_id(self) -> None:
        ref = DispatchRef(run_id="r", repository="ci-agent-r", branch="ci-agent/r")
        with pytest.raises(ValueError, match="external_run_id"):
            JenkinsAdapter(_FakeJenkinsClient()).poll_status(ref)


class TestFetchStepLogs:
    def test_returns_console_log_text(self) -> None:
        adapter = JenkinsAdapter(_FakeJenkinsClient())
        assert adapter.fetch_step_logs(self._ref_from_helper(), "sast") == (
            "console of ci-agent-run-1 #5"
        )

    @staticmethod
    def _ref_from_helper() -> DispatchRef:
        return DispatchRef(
            run_id="run-1",
            repository="ci-agent-run-1",
            branch="ci-agent/run-1",
            external_run_id="5",
        )

    def test_requires_external_run_id(self) -> None:
        ref = DispatchRef(run_id="r", repository="ci-agent-r", branch="ci-agent/r")
        with pytest.raises(JenkinsAPIError, match="not resolved"):
            JenkinsAdapter(_FakeJenkinsClient()).fetch_step_logs(ref, "sast")


class TestResultMappingTable:
    @pytest.mark.parametrize(
        ("result", "building", "expected"),
        [
            ("SUCCESS", False, StageStatus.PASSED),
            ("FAILURE", False, StageStatus.FAILED),
            ("UNSTABLE", False, StageStatus.FAILED),  # unstable is NOT a pass
            ("ABORTED", False, StageStatus.CANCELLED),
            ("NOT_BUILT", False, StageStatus.SKIPPED),
            (None, True, StageStatus.RUNNING),
        ],
    )
    def test_explicit_mapping(
        self, result: str | None, building: bool, expected: StageStatus
    ) -> None:
        assert map_jenkins_result(result, building) is expected

    def test_null_result_not_building_fails_closed(self) -> None:
        assert map_jenkins_result(None, False) is StageStatus.FAILED

    def test_unknown_result_fails_closed(self) -> None:
        assert map_jenkins_result("WEIRD", False) is StageStatus.FAILED

    def test_mapping_table_contents(self) -> None:
        """Exactly the five documented Jenkins result values — a null result
        is handled by the building flag (running) or fails closed (failed),
        never guessed from the table."""
        assert set(JENKINS_RESULT_TO_STAGE_STATUS) == {
            "SUCCESS",
            "FAILURE",
            "UNSTABLE",
            "ABORTED",
            "NOT_BUILT",
        }
        assert None not in JENKINS_RESULT_TO_STAGE_STATUS


class TestJenkinsClientHttp:
    """respx-mocked transport: auth, error mapping, endpoints."""

    def test_construction_without_full_config_fails_loud(self) -> None:
        with pytest.raises(JenkinsAPIError, match="JENKINS_URL"):
            JenkinsClient("", "user", "token")
        with pytest.raises(JenkinsAPIError, match="JENKINS"):
            JenkinsClient("http://j", "", "token")

    @respx.mock
    def test_build_job_returns_queue_id_from_location(self) -> None:
        respx.post(f"{JENKINS_BASE}/job/ci-agent-run-1/build").respond(
            201, headers={"Location": f"{JENKINS_BASE}/queue/item/77/"}
        )
        client = JenkinsClient(JENKINS_BASE, "user", "token")
        assert client.build_job("ci-agent-run-1") == 77

    @respx.mock
    def test_build_job_without_location_raises(self) -> None:
        respx.post(f"{JENKINS_BASE}/job/j/build").respond(201)
        client = JenkinsClient(JENKINS_BASE, "user", "token")
        with pytest.raises(JenkinsAPIError, match="queue item"):
            client.build_job("j")

    @respx.mock
    def test_create_job_falls_back_to_config_update_on_exists(self) -> None:
        respx.post(f"{JENKINS_BASE}/createItem").respond(400, text="already exists")
        update = respx.post(f"{JENKINS_BASE}/job/j/config.xml").respond(200)
        client = JenkinsClient(JENKINS_BASE, "user", "token")
        client.create_job("j", "<xml/>")
        assert update.called

    @respx.mock
    def test_http_error_raises_jenkins_api_error_with_status(self) -> None:
        respx.get(f"{JENKINS_BASE}/job/j/5/api/json").respond(500, text="boom")
        client = JenkinsClient(JENKINS_BASE, "user", "token")
        with pytest.raises(JenkinsAPIError) as excinfo:
            client.get_build("j", "5")
        assert excinfo.value.status_code == 500

    @respx.mock
    def test_transport_error_raises_jenkins_api_error(self) -> None:
        respx.get(f"{JENKINS_BASE}/job/j/5/api/json").mock(side_effect=httpx.ConnectError("nope"))
        client = JenkinsClient(JENKINS_BASE, "user", "token")
        with pytest.raises(JenkinsAPIError) as excinfo:
            client.get_build("j", "5")
        assert excinfo.value.status_code is None

    @respx.mock
    def test_get_build_log_returns_console_text(self) -> None:
        respx.get(f"{JENKINS_BASE}/job/j/5/consoleText").respond(200, text="log line")
        client = JenkinsClient(JENKINS_BASE, "user", "token")
        assert client.get_build_log("j", "5") == "log line"

    @respx.mock
    def test_requests_use_basic_auth(self) -> None:
        route = respx.get(f"{JENKINS_BASE}/job/j/5/api/json").respond(
            200, json={"result": None, "building": True}
        )
        client = JenkinsClient(JENKINS_BASE, "user", "token")
        client.get_build("j", "5")
        authorization = route.calls[0].request.headers["Authorization"]
        assert authorization.startswith("Basic ")


def test_job_name_convention() -> None:
    assert job_name_for_run("abc-123") == "ci-agent-abc-123"
