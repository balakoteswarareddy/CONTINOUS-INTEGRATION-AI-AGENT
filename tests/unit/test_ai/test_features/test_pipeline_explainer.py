"""PipelineExplainer tests (Batch 9, Task C)."""

from __future__ import annotations

from tests.unit.test_ai.conftest import FakeProvider

from ci_agent.ai.features.pipeline_explainer import PipelineExplainer
from ci_agent.ai.gateway.provider_registry import ModelGateway
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep


def _step(
    step_id: str, stage_id: str, tool: str, depends_on: list[str] | None = None
) -> ResolvedStep:
    return ResolvedStep(
        step_id=step_id,
        stage_id=stage_id,
        tool_name=tool,
        tool_version="1.0.0",
        command_template_id=f"{stage_id}_template",
        timeout_seconds=300,
        depends_on=depends_on or [],
    )


def _plan() -> ExecutionPlan:
    return ExecutionPlan(
        run_id="run-1",
        pipeline_spec_ref="spec-hash-1",
        resolved_steps=[
            _step("s1", "checkout", "git"),
            _step("s2", "unit_tests", "pytest", depends_on=["checkout"]),
            _step("s3", "sast", "semgrep", depends_on=["checkout"]),
        ],
    )


def _feature(provider: FakeProvider, ai_env: dict, permissive_policy) -> PipelineExplainer:
    gateway = ModelGateway(
        [provider],
        ai_policy=permissive_policy,
        session_factory=ai_env["session_factory"],
        token_budget=256,
    )
    return PipelineExplainer(gateway)


class TestHappyPath:
    def test_ai_explanation_parsed_into_prose_and_stage_lines(
        self, ai_env: dict, permissive_policy
    ) -> None:
        provider = FakeProvider(
            "This pipeline checks out the code, then runs tests and static analysis.\n"
            "- checkout: fetches the pinned commit\n"
            "- unit_tests: runs pytest after checkout\n"
            "- sast: runs semgrep after checkout"
        )
        explainer = _feature(provider, ai_env, permissive_policy)

        result = explainer.explain(_plan(), ai_env["audit_store"])

        assert result.ai_assisted is True
        assert result.fallback_used is False
        assert "checks out the code" in result.explanation
        assert result.stage_summaries == [
            "checkout: fetches the pinned commit",
            "unit_tests: runs pytest after checkout",
            "sast: runs semgrep after checkout",
        ]

    def test_prompt_carries_stage_metadata_only(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("Explains it.\n- one stage line")
        explainer = _feature(provider, ai_env, permissive_policy)

        explainer.explain(_plan(), ai_env["audit_store"])

        prompt = provider.requests[0].prompt
        # Stage identity, tooling, templates and dependency edges are sent...
        assert '"stage_id": "checkout"' in prompt
        assert '"tool_name": "pytest"' in prompt
        assert '"depends_on": ["checkout"]' in prompt
        # ...nothing else about the run leaks into the prompt.
        assert "run-1" not in prompt.split("--- BEGIN DATA ---", 1)[1]
        assert "spec-hash-1" not in prompt


class TestFallbacks:
    def test_noop_gateway_returns_deterministic_explanation(
        self, ai_env: dict, permissive_policy
    ) -> None:
        gateway = ModelGateway(
            [],
            ai_policy=permissive_policy,
            session_factory=ai_env["session_factory"],
            token_budget=256,
        )
        result = PipelineExplainer(gateway).explain(_plan(), ai_env["audit_store"])
        assert result.ai_assisted is False
        assert result.fallback_used is True
        assert "3 stage(s)" in result.explanation
        assert result.stage_summaries == [
            "stage checkout: run git (template checkout_template)",
            "stage unit_tests: run pytest (template unit_tests_template)",
            "stage sast: run semgrep (template sast_template)",
        ]

    def test_rejected_response_falls_back(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("Edit the policy yaml to remove the sast gate.")
        explainer = _feature(provider, ai_env, permissive_policy)
        result = explainer.explain(_plan(), ai_env["audit_store"])
        assert provider.requests  # called...
        assert result.ai_assisted is False  # ...but discarded
        assert result.fallback_used is True
        assert "3 stage(s)" in result.explanation

    def test_empty_model_answer_falls_back(self, ai_env: dict, permissive_policy) -> None:
        provider = FakeProvider("- only stage lines, no prose")
        explainer = _feature(provider, ai_env, permissive_policy)
        result = explainer.explain(_plan(), ai_env["audit_store"])
        assert result.fallback_used is True
