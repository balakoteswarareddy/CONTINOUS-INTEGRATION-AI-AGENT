"""Planner: template-based ExecutionPlan generation (Batch 3, Task B; Section 4.2/5.1).

100% template-driven for the MVP (Report Section 13 Phase 1: "templates... no
autonomous execution beyond approved pipeline steps"). The Planner never
approves anything itself: every template tool/version must be approved by the
governed tool policy, else :class:`UnapprovedToolError` (Section 18: "the
model may propose, but policy approves" — the same enforcement discipline
applies to templates). Plan approval through the Policy Decision Point is a
separate call the orchestrator makes (components stay composable and
separate).
"""

from __future__ import annotations

import hashlib

from ci_agent.audit.audit_store import canonical_json
from ci_agent.core.models.execution_plan import ExecutionPlan, ResolvedStep, RetryPolicy
from ci_agent.core.models.pipeline_spec import PipelineSpec, StageDefinition
from ci_agent.core.models.policy_spec import PolicySpec
from ci_agent.planner.templates.template_registry import TemplateRegistry
from ci_agent.resolver.project_profile import ProjectProfile

GATE_TOOL_PREFIX = "internal."


class UnapprovedToolError(Exception):
    """A stage template references a tool/version not approved by tool policy.

    Lists every offending tool@version at once. Never silently substituted
    (Batch 3 guardrail).
    """

    def __init__(self, unapproved: list[str]) -> None:
        self.unapproved = unapproved
        super().__init__("Unapproved tools in stage templates: " + "; ".join(unapproved))


class TemplateMismatchError(Exception):
    """A PipelineSpec stage has no corresponding template stage (hard fail)."""


class Planner:
    """Builds a validated ExecutionPlan from approved stack templates."""

    def __init__(self, template_registry: TemplateRegistry, policy_spec: PolicySpec) -> None:
        self._registry = template_registry
        self._policy = policy_spec

    def build_execution_plan(
        self,
        project_profile: ProjectProfile,
        pipeline_spec: PipelineSpec,
        policy_spec_version: str,
        *,
        run_id: str,
    ) -> ExecutionPlan:
        """Resolve ``pipeline_spec`` stages into concrete steps for the stack.

        Raises ``ValueError`` if ``policy_spec_version`` does not match the
        governed PolicySpec this Planner was built with (prevents planning
        against a policy generation the caller does not realize is in force).
        """
        if policy_spec_version != self._policy.policy_version:
            raise ValueError(
                f"policy_spec_version {policy_spec_version!r} does not match governed "
                f"policy version {self._policy.policy_version!r}"
            )

        template = self._registry.get_template(project_profile.language_stack)
        entries = {entry["stage_id"]: entry for entry in template["stages"]}

        pipeline_stage_ids = {stage.id for stage in pipeline_spec.stages}
        missing = pipeline_stage_ids - set(entries)
        if missing:
            raise TemplateMismatchError(
                f"no template stage exists for pipeline stage(s) {sorted(missing)} "
                f"(stack {project_profile.language_stack!r})"
            )
        # Template stages the pipeline spec does not use are simply not planned:
        # the spec is the source of truth for WHAT runs, the template for HOW.

        ordered_stages = self._topological_order(pipeline_spec)

        unapproved: list[str] = []
        steps: list[ResolvedStep] = []
        for stage in ordered_stages:
            entry = entries[stage.id]
            tool_name = str(entry["tool_name"])
            tool_version = str(entry["tool_version"])
            if not tool_name.startswith(GATE_TOOL_PREFIX):
                approved_version = self._policy.tool_policy.approved_tool_versions.get(tool_name)
                if approved_version != tool_version:
                    unapproved.append(f"{tool_name}@{tool_version} (stage {stage.id!r})")
                    continue
            steps.append(
                ResolvedStep(
                    step_id=f"{stage.id}.{tool_name}",
                    stage_id=stage.id,
                    tool_name=tool_name,
                    tool_version=tool_version,
                    container_image=entry.get("container_image"),
                    command_template_id=str(entry["command_template_id"]),
                    timeout_seconds=int(entry["timeout_seconds"]),
                    retry_policy=RetryPolicy(
                        max_retries=int(entry["max_retries"]),
                        retryable=bool(entry["retryable"]),
                    ),
                    resource_limits=dict(entry.get("resource_limits", {})),
                    expected_outputs=list(entry.get("expected_outputs", [])),
                    depends_on=list(stage.depends_on),
                )
            )

        if unapproved:
            raise UnapprovedToolError(unapproved)

        return ExecutionPlan(
            run_id=run_id,
            pipeline_spec_ref=self.pipeline_spec_hash(pipeline_spec),
            resolved_steps=steps,
            identities=[],  # scoped identity binding arrives with runner adapters
        )

    @staticmethod
    def pipeline_spec_hash(pipeline_spec: PipelineSpec) -> str:
        """Stable content hash of a PipelineSpec: sha256 of its canonical JSON."""
        digest = hashlib.sha256(
            canonical_json(pipeline_spec.model_dump(mode="json")).encode("utf-8")
        )
        return f"sha256:{digest.hexdigest()}"

    @staticmethod
    def _topological_order(pipeline_spec: PipelineSpec) -> list[StageDefinition]:
        """Order stages so every stage appears after its depends_on (Kahn, stable)."""
        stages = list(pipeline_spec.stages)
        ordered: list[StageDefinition] = []
        resolved: set[str] = set()
        pending = stages
        while pending:
            ready = [stage for stage in pending if all(dep in resolved for dep in stage.depends_on)]
            if not ready:  # PipelineSpec already rejects cycles; defensive guard.
                raise ValueError("pipeline_spec stages contain a dependency cycle")
            for stage in ready:
                ordered.append(stage)
                resolved.add(stage.id)
            pending = [stage for stage in pending if stage.id not in resolved]
        return ordered
