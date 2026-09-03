"""Telemetry convention constants (Batch 8, Task E)."""

from __future__ import annotations

import pytest

from ci_agent.telemetry import conventions
from ci_agent.telemetry.conventions import (
    CI_AGENT_POLICY_DECISION,
    CI_AGENT_POLICY_VERSION,
    CI_AGENT_RUN_ID,
    CI_AGENT_RUNNER,
    CI_AGENT_STAGE_ID,
    CICD_PIPELINE_NAME,
    CICD_PIPELINE_RUN_ID,
    CICD_PIPELINE_TASK_NAME,
    CICD_PIPELINE_TASK_RUN_ID,
    CICD_PIPELINE_TASK_TYPE,
    CICD_WORKER_ID,
    CICD_WORKER_STATE,
)

ALL_CONSTANTS = [
    CICD_PIPELINE_NAME,
    CICD_PIPELINE_RUN_ID,
    CICD_PIPELINE_TASK_NAME,
    CICD_PIPELINE_TASK_RUN_ID,
    CICD_PIPELINE_TASK_TYPE,
    CICD_WORKER_ID,
    CICD_WORKER_STATE,
    CI_AGENT_RUN_ID,
    CI_AGENT_STAGE_ID,
    CI_AGENT_RUNNER,
    CI_AGENT_POLICY_DECISION,
    CI_AGENT_POLICY_VERSION,
]


def test_every_constant_is_a_non_empty_string() -> None:
    for constant in ALL_CONSTANTS:
        assert isinstance(constant, str)
        assert constant.strip() == constant
        assert len(constant) > 0


def test_no_two_constants_share_the_same_value() -> None:
    """Collision test: distinct concepts must keep distinct field names."""
    values = list(ALL_CONSTANTS)
    assert len(values) == len(set(values))


def test_otel_constants_follow_the_cicd_namespace() -> None:
    """The convention-covered fields use the OTel CI/CD dotted namespace."""
    for constant in (
        CICD_PIPELINE_NAME,
        CICD_PIPELINE_RUN_ID,
        CICD_PIPELINE_TASK_NAME,
        CICD_PIPELINE_TASK_RUN_ID,
        CICD_PIPELINE_TASK_TYPE,
        CICD_WORKER_ID,
        CICD_WORKER_STATE,
    ):
        assert constant.startswith("cicd.")


def test_internal_extensions_use_the_ci_agent_prefix() -> None:
    for constant in (
        CI_AGENT_RUN_ID,
        CI_AGENT_STAGE_ID,
        CI_AGENT_RUNNER,
        CI_AGENT_POLICY_DECISION,
        CI_AGENT_POLICY_VERSION,
    ):
        assert constant.startswith("ci_agent.")


def test_module_dunder_all_matches_the_constant_list() -> None:
    exported = {getattr(conventions, name) for name in conventions.__all__}
    assert exported == set(ALL_CONSTANTS)


@pytest.mark.parametrize("constant", ALL_CONSTANTS)
def test_constants_are_hashable_usable_as_dict_keys(constant: str) -> None:
    payload = {constant: "value"}
    assert payload[constant] == "value"
