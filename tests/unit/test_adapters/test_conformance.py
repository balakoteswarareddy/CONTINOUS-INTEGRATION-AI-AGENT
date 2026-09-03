"""Adapter conformance suite (Batch 8, Task D — Section 13 Phase 3
"adapter certification and conformance tests").

THE CONTRACT: every registered runner adapter must satisfy the same
behavioural checks against the RunnerAdapter interface as written in
``src/ci_agent/adapters/base.py`` — the adapters conform to the interface,
never the other way around.

ZERO LIVE CREDENTIALS: each adapter under test is instantiated with its
external client MOCKED (hand-rolled deterministic fakes, following the
existing project test patterns). If a check here needs real GitLab/Jenkins/
GitHub access, it is an integration test and belongs in tests/integration/
(the live-dispatch files there), NOT in this suite.

EXTENSION PATTERN (read before adding an adapter): adding a NEW adapter in a
future batch requires ONLY appending one factory to ``ADAPTER_FACTORIES``
below — no new test cases, no edits to the checks. The factory must return a
fully-configured adapter whose external client is a mock that satisfies the
RunnerAdapter method contracts (compile -> artifact; dispatch -> ref with
branch; poll_status -> snapshot; fetch_step_logs -> str). Everything else is
generic and driven through the interface alone.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
from typing import Any, ClassVar

import pytest
import yaml

from ci_agent.adapters.base import (
    CompiledArtifact,
    DispatchRef,
    RunnerAdapter,
    RunnerStatusSnapshot,
    StageStatus,
    StageStatusView,
)
from ci_agent.adapters.github_actions.adapter import GitHubActionsAdapter
from ci_agent.adapters.gitlab_ci.adapter import GitLabCIAdapter
from ci_agent.adapters.jenkins.adapter import JenkinsAdapter
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy

RUN_ID = "conformance-run-1"
SECRET_MARKER = "ghp_DEFINITELY_A_SECRET_VALUE_0123456789"


# --------------------------------------------------------------------------
# Mocked external clients (deterministic; no HTTP, no credentials)
# --------------------------------------------------------------------------


class _MockGitHubClient:
    def create_branch(self, repo: str, branch: str, from_sha: str) -> None:
        return None

    def create_or_update_file(
        self, repo: str, path: str, content: str, branch: str, message: str
    ) -> dict[str, Any]:
        return {"path": path}

    def trigger_workflow_dispatch(
        self, repo: str, workflow_file: str, ref: str, inputs: dict[str, str] | None = None
    ) -> None:
        return None

    def list_workflow_runs_for_branch(
        self, repo: str, branch: str, per_page: int = 10
    ) -> list[dict[str, Any]]:
        return [{"head_branch": branch, "id": 9001}]

    def get_workflow_run(self, repo: str, run_id: str) -> dict[str, Any]:
        return {"status": "completed", "conclusion": "success"}

    def get_check_runs(self, repo: str, ref: str) -> list[dict[str, Any]]:
        return [
            {"name": "format_lint", "status": "completed", "conclusion": "success"},
            {"name": "ci-agent-results", "status": "completed", "conclusion": "success"},
        ]

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        class _Response:
            status_code = 200
            headers: ClassVar[dict[str, str]] = {}
            text = ""
            content = b""

        return _Response()


class _MockGitLabClient:
    def create_branch(self, project_id: str, branch: str, ref: str) -> dict[str, Any]:
        return {"name": branch}

    def create_or_update_file(
        self, project_id: str, file_path: str, content: str, branch: str, commit_message: str
    ) -> dict[str, Any]:
        return {"file_path": file_path}

    def trigger_pipeline(
        self, project_id: str, ref: str, variables: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return {"id": 42, "ref": ref}

    def get_pipeline(self, project_id: str, pipeline_id: str) -> dict[str, Any]:
        return {"id": int(pipeline_id), "status": "success"}

    def get_pipeline_jobs(self, project_id: str, pipeline_id: str) -> list[dict[str, Any]]:
        return [{"name": "format_lint", "status": "success", "id": 101}]

    def get_job_log(self, project_id: str, job_id: str) -> str:
        return "log text"

    def post_commit_status(
        self, project_id: str, sha: str, state: str, name: str, description: str
    ) -> dict[str, Any]:
        return {"state": state}


class _MockJenkinsClient:
    def __init__(self) -> None:
        self.config_xml = ""

    def create_job(self, name: str, config_xml: str) -> None:
        self.config_xml = config_xml

    def build_job(self, name: str, parameters: dict[str, str] | None = None) -> int:
        return 77

    def get_queue_item(self, queue_id: int) -> dict[str, Any]:
        return {"id": queue_id, "executable": {"number": 5}}

    def get_build(self, name: str, build_number: str) -> dict[str, Any]:
        return {"result": "SUCCESS", "building": False, "number": int(build_number)}

    def get_build_log(self, name: str, build_number: str) -> str:
        return "console text"


# --------------------------------------------------------------------------
# THE parametrize list: append new adapters HERE (and only here)
# --------------------------------------------------------------------------

ADAPTER_FACTORIES: dict[str, Any] = {
    "github_actions": lambda: GitHubActionsAdapter(_MockGitHubClient()),  # type: ignore[arg-type]
    "gitlab_ci": lambda: GitLabCIAdapter(_MockGitLabClient()),  # type: ignore[arg-type]
    "jenkins": lambda: JenkinsAdapter(_MockJenkinsClient()),  # type: ignore[arg-type]
}


# The RunnerAdapter interface as written — frozen signatures used by the
# structural check (a conforming adapter may never modify the base class).
# Annotations are compared quote-normalized: base.py uses
# `from __future__ import annotations`, so inspect renders them as strings.
def _normalized_signature(method_name: str) -> str:
    method = getattr(RunnerAdapter, method_name)
    return str(inspect.signature(method)).replace("'", "")


_EXPECTED_BASE_SIGNATURES: dict[str, str] = {
    "compile": (
        "(self, plan: ExecutionPlan, metadata: dict[str, str] | None = None)" " -> CompiledArtifact"
    ),
    "dispatch": "(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef",
    "poll_status": "(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot",
    "fetch_step_logs": "(self, dispatch_ref: DispatchRef, step_id: str) -> str",
}


def _metadata() -> dict[str, str]:
    return {
        "repository": "example-org/payments-api",
        "source_sha": "abc123def456",
        # A fake secret-looking value: must NEVER appear in compiled content
        # (Section 18: "Secrets are never embedded in generated YAML or model
        # context") — expressed as an automated conformance check.
        "credential": SECRET_MARKER,
    }


def _conformance_plan() -> ExecutionPlan:
    """A plan exercising tool steps, a gate step and a scan step."""
    stages = [
        ("checkout", "git", "2.43", None, "checkout.default", []),
        ("format_lint", "ruff", "0.6.0", "python:3.11-slim", "lint.ruff", ["checkout"]),
        ("sast", "bandit", "1.7.9", "python:3.11-slim", "sast.bandit", ["format_lint"]),
        (
            "policy_gate",
            "internal.policy_gate",
            "internal",
            None,
            "internal.policy_gate",
            ["sast"],
        ),
    ]
    return ExecutionPlan(
        run_id=RUN_ID,
        pipeline_spec_ref="sha256:abc",
        resolved_steps=[
            ResolvedStep(
                step_id=f"{sid}.{tool}",
                stage_id=sid,
                tool_name=tool,
                tool_version=version,
                container_image=image,
                command_template_id=template,
                timeout_seconds=300,
                retry_policy=RetryPolicy(),
                depends_on=deps,
            )
            for sid, tool, version, image, template, deps in stages
        ],
    )


@pytest.fixture()
def adapter(request: pytest.FixtureRequest) -> RunnerAdapter:
    return ADAPTER_FACTORIES[request.param]()


@pytest.mark.parametrize("adapter", sorted(ADAPTER_FACTORIES), indirect=True)
class TestCompileConformance:
    def test_compile_returns_compiled_artifact_with_kind_and_content(
        self, adapter: RunnerAdapter
    ) -> None:
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        assert isinstance(artifact, CompiledArtifact)
        # kind is a non-empty string
        assert isinstance(artifact.kind, str) and artifact.kind
        # content is non-empty
        assert isinstance(artifact.content, str) and artifact.content.strip()

    def test_content_is_non_empty_and_secret_free(self, adapter: RunnerAdapter) -> None:
        """Section 18: secrets are never embedded in generated YAML or model
        context — expressed as an automated conformance check."""
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        assert artifact.content.strip()
        # No raw secrets or literal credential values in compiled output.
        assert SECRET_MARKER not in artifact.content

    def test_content_hash_is_a_correct_sha256(self, adapter: RunnerAdapter) -> None:
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        assert artifact.content_hash.startswith("sha256:")
        digest = hashlib.sha256(artifact.content.encode("utf-8")).hexdigest()
        assert artifact.content_hash == f"sha256:{digest}"

    def test_yaml_adapters_emit_parseable_yaml(self, adapter: RunnerAdapter) -> None:
        """GitHub/GitLab compile to YAML — round-trip parseable. Jenkins
        compiles to a declarative Jenkinsfile (Groovy text) — validated
        structurally instead. The format is derived from the artifact kind,
        so the check stays generic for future adapters."""
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        if artifact.kind in ("github_actions_workflow", "gitlab_ci_pipeline"):
            parsed = yaml.safe_load(artifact.content)
            assert isinstance(parsed, dict)
        else:  # declarative pipeline text (jenkins)
            assert "pipeline {" in artifact.content
            assert artifact.content.count("{") == artifact.content.count("}")

    def test_internal_steps_carry_no_tool_commands(self, adapter: RunnerAdapter) -> None:
        """Gate stages (internal.*) are control-plane orchestrated — no real
        tool command may appear for them in the compiled output."""
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        # The internal step is policy_gate; its tool command would be a
        # registry command for a REAL tool — internal.* never consults the
        # registry, so no tool command string may be tied to it.
        internal_section = self._internal_section(artifact, request=None)
        for forbidden in ("bandit", "ruff check", "gitleaks", "pip-audit"):
            assert forbidden not in internal_section

    @staticmethod
    def _internal_section(artifact: CompiledArtifact, request: Any) -> str:
        """Best-effort extraction of the internal-stage section per format."""
        if artifact.kind == "github_actions_workflow":
            parsed = yaml.safe_load(artifact.content)
            job = parsed["jobs"].get("stage-policy_gate")
            return str(job)
        if artifact.kind == "gitlab_ci_pipeline":
            parsed = yaml.safe_load(artifact.content)
            return str(parsed.get("policy_gate"))
        # jenkins: the stage block between stage('policy_gate') and the next
        block = artifact.content.split("stage('policy_gate')", 1)
        if len(block) < 2:
            return ""
        tail = block[1]
        end = tail.find("stage('")
        return tail[: end if end > 0 else len(tail)]


@pytest.mark.parametrize("adapter", sorted(ADAPTER_FACTORIES), indirect=True)
class TestDispatchConformance:
    def test_dispatch_returns_dispatch_ref_with_conventions(self, adapter: RunnerAdapter) -> None:
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        ref = adapter.dispatch(artifact, RUN_ID)
        assert isinstance(ref, DispatchRef)
        assert ref.run_id == RUN_ID
        assert ref.branch == f"ci-agent/{RUN_ID}"  # the dispatch convention
        # external_run_id is a non-empty string or None (async resolution ok)
        assert ref.external_run_id is None or (
            isinstance(ref.external_run_id, str) and ref.external_run_id
        )


@pytest.mark.parametrize("adapter", sorted(ADAPTER_FACTORIES), indirect=True)
class TestPollStatusConformance:
    def test_poll_status_returns_snapshot_in_our_vocabulary(self, adapter: RunnerAdapter) -> None:
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        ref = adapter.dispatch(artifact, RUN_ID)
        if ref.external_run_id is None:
            pytest.skip("adapter resolves external_run_id asynchronously")
        snapshot = adapter.poll_status(ref)
        assert isinstance(snapshot, RunnerStatusSnapshot)
        assert snapshot.run_id == ref.run_id
        assert isinstance(snapshot.status, StageStatus)
        assert isinstance(snapshot.completed, bool)
        for view in snapshot.stages:
            assert isinstance(view, StageStatusView)
            assert isinstance(view.status, StageStatus)


@pytest.mark.parametrize("adapter", sorted(ADAPTER_FACTORIES), indirect=True)
class TestFetchStepLogsConformance:
    def test_fetch_step_logs_returns_a_string(self, adapter: RunnerAdapter) -> None:
        artifact = adapter.compile(_conformance_plan(), metadata=_metadata())
        ref = adapter.dispatch(artifact, RUN_ID)
        if ref.external_run_id is None:
            pytest.skip("adapter resolves external_run_id asynchronously")
        logs = adapter.fetch_step_logs(ref, "format_lint")
        assert isinstance(logs, str)  # may be empty — but must BE a string


@pytest.mark.parametrize("adapter_name", sorted(ADAPTER_FACTORIES))
class TestInterfaceIntegrity:
    def test_base_class_signatures_unchanged_after_adapter_import(self, adapter_name: str) -> None:
        """Structural check: importing (and using) an adapter must not modify
        the RunnerAdapter base class or its method signatures."""
        importlib.import_module("ci_agent.adapters.base")
        for method_name, expected in _EXPECTED_BASE_SIGNATURES.items():
            signature = _normalized_signature(method_name)
            assert signature == expected, (
                f"RunnerAdapter.{method_name} signature changed: " f"{signature!r} != {expected!r}"
            )
        # The abstract method set is exactly the four interface methods.
        assert RunnerAdapter.__abstractmethods__ == frozenset(
            {"compile", "dispatch", "poll_status", "fetch_step_logs"}
        )

    def test_adapter_is_a_runner_adapter_subclass(self, adapter_name: str) -> None:
        adapter = ADAPTER_FACTORIES[adapter_name]()
        assert isinstance(adapter, RunnerAdapter)
