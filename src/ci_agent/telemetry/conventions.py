"""Normalized, OpenTelemetry-aligned telemetry (Batch 8, Task E; Section 9).

The field-name constants below follow the OpenTelemetry CI/CD semantic
conventions (architecture report §9, reference [8]) so the control plane's
telemetry vocabulary is PORTABLE across runner implementations. Deliberately
NOT a dependency on the opentelemetry-sdk package: the transport (stdlib
``logging`` with a JSON formatter) is swappable later — what matters now, and
what these constants pin down, is the field vocabulary.
"""

from __future__ import annotations

# OpenTelemetry CI/CD semantic conventions (report §9, ref [8]).
# Field names follow https://opentelemetry.io/docs/specs/semconv/cicd/
CICD_PIPELINE_NAME = "cicd.pipeline.name"
CICD_PIPELINE_RUN_ID = "cicd.pipeline.run.id"
CICD_PIPELINE_TASK_NAME = "cicd.pipeline.task.name"
CICD_PIPELINE_TASK_RUN_ID = "cicd.pipeline.task.run.id"
CICD_PIPELINE_TASK_TYPE = "cicd.pipeline.task.type"
CICD_WORKER_ID = "cicd.worker.id"
CICD_WORKER_STATE = "cicd.worker.state"

# Internal extensions (prefixed ci_agent. to avoid collision).
CI_AGENT_RUN_ID = "ci_agent.run.id"
CI_AGENT_STAGE_ID = "ci_agent.stage.id"
CI_AGENT_RUNNER = "ci_agent.runner"
CI_AGENT_POLICY_DECISION = "ci_agent.policy.decision"
CI_AGENT_POLICY_VERSION = "ci_agent.policy.version"

__all__ = [
    "CICD_PIPELINE_NAME",
    "CICD_PIPELINE_RUN_ID",
    "CICD_PIPELINE_TASK_NAME",
    "CICD_PIPELINE_TASK_RUN_ID",
    "CICD_PIPELINE_TASK_TYPE",
    "CICD_WORKER_ID",
    "CICD_WORKER_STATE",
    "CI_AGENT_POLICY_DECISION",
    "CI_AGENT_POLICY_VERSION",
    "CI_AGENT_RUNNER",
    "CI_AGENT_RUN_ID",
    "CI_AGENT_STAGE_ID",
]
