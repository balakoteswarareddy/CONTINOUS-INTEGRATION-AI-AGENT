"""TelemetryEmitter: JSON emission + never-raise contract (Batch 8, Task E)."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

import pytest

from ci_agent.core.models.common import StageStatus
from ci_agent.telemetry import conventions
from ci_agent.telemetry.emitter import JsonFormatter, TelemetryEmitter
from ci_agent.telemetry.pipeline_event import PipelineRunEvent, StageEvent, WorkerEvent


class _CaptureHandler(logging.Handler):
    """Collects formatted lines so tests can parse real log output."""

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(JsonFormatter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture()
def capture() -> tuple[_CaptureHandler, TelemetryEmitter]:
    logger = logging.getLogger("ci_agent.telemetry.test")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = _CaptureHandler()
    logger.addHandler(handler)
    emitter = TelemetryEmitter(logger=logger)
    return handler, emitter


def _last_json(handler: _CaptureHandler) -> dict[str, object]:
    assert handler.lines, "no telemetry line was emitted"
    return dict(json.loads(handler.lines[-1]))


class TestPipelineRunEmission:
    def test_emits_valid_json_with_otel_field_names(self, capture) -> None:
        handler, emitter = capture
        emitter.emit_pipeline_run(
            PipelineRunEvent(
                event_type="run_started",
                pipeline_name="example-org/payments-api",
                run_id="run-1",
                runner="github_actions",
                status=StageStatus.RUNNING,
                started_at=datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC),
            )
        )
        payload = _last_json(handler)
        assert payload["event"] == "pipeline_run"
        assert payload["event_type"] == "run_started"
        assert payload[conventions.CICD_PIPELINE_NAME] == "example-org/payments-api"
        assert payload[conventions.CICD_PIPELINE_RUN_ID] == "run-1"
        assert payload[conventions.CI_AGENT_RUN_ID] == "run-1"
        assert payload[conventions.CI_AGENT_RUNNER] == "github_actions"
        assert payload["status"] == "running"
        assert payload["started_at"] == "2026-09-03T12:00:00+00:00"

    def test_attributes_are_merged_into_the_payload(self, capture) -> None:
        handler, emitter = capture
        emitter.emit_pipeline_run(
            PipelineRunEvent(
                event_type="run_terminal",
                pipeline_name="p",
                run_id="run-2",
                runner="gitlab_ci",
                status=StageStatus.PASSED,
                attributes={"phase": "phase_b"},
            )
        )
        payload = _last_json(handler)
        assert payload["phase"] == "phase_b"
        assert payload["completed_at"] is None


class TestStageEmission:
    def test_emits_valid_json_with_otel_field_names(self, capture) -> None:
        handler, emitter = capture
        emitter.emit_stage(
            StageEvent(
                run_id="run-3",
                stage_id="sast",
                task_type="scan",
                status=StageStatus.PASSED,
                duration_ms=1234,
                exit_code=0,
            )
        )
        payload = _last_json(handler)
        assert payload["event"] == "stage"
        assert payload[conventions.CICD_PIPELINE_RUN_ID] == "run-3"
        assert payload[conventions.CICD_PIPELINE_TASK_NAME] == "sast"
        assert payload[conventions.CI_AGENT_STAGE_ID] == "sast"
        assert payload[conventions.CICD_PIPELINE_TASK_TYPE] == "scan"
        assert payload["status"] == "passed"
        assert payload["duration_ms"] == 1234
        assert payload["exit_code"] == 0


class TestWorkerEmission:
    def test_emits_valid_json_with_otel_field_names(self, capture) -> None:
        handler, emitter = capture
        emitter.emit_worker(
            WorkerEvent(
                worker_id="runner-7",
                worker_state="online",
                runner="jenkins",
            )
        )
        payload = _last_json(handler)
        assert payload["event"] == "worker"
        assert payload[conventions.CICD_WORKER_ID] == "runner-7"
        assert payload[conventions.CICD_WORKER_STATE] == "online"
        assert payload[conventions.CI_AGENT_RUNNER] == "jenkins"


class TestNeverRaiseContract:
    def test_emitter_does_not_propagate_logger_exceptions(self) -> None:
        """Section 10: telemetry must never be a failure point."""
        logger = logging.getLogger("ci_agent.telemetry.broken")
        logger.propagate = False

        def _explode(payload: object) -> None:
            raise RuntimeError("logger exploded")

        logger.info = _explode  # type: ignore[method-assign]
        logger.error = _explode  # type: ignore[method-assign]
        emitter = TelemetryEmitter(logger=logger)

        # Must return normally — no exception may escape, even when both the
        # primary emission AND the error indicator fail.
        emitter.emit_pipeline_run(
            PipelineRunEvent(
                event_type="run_started",
                pipeline_name="p",
                run_id="run-x",
                runner="github_actions",
                status=StageStatus.RUNNING,
            )
        )
        emitter.emit_stage(
            StageEvent(run_id="run-x", stage_id="s", task_type="t", status=StageStatus.RUNNING)
        )
        emitter.emit_worker(WorkerEvent(worker_id="w", worker_state="online", runner="r"))

    def test_every_line_is_one_json_object(self, capture) -> None:
        handler, emitter = capture
        emitter.emit_stage(
            StageEvent(
                run_id="run-4",
                stage_id="unit_tests",
                task_type="test",
                status=StageStatus.FAILED,
                exit_code=1,
                attributes={"action": "created"},
            )
        )
        assert len(handler.lines) == 1
        parsed = json.loads(handler.lines[0])
        assert isinstance(parsed, dict)
        assert parsed[conventions.CI_AGENT_STAGE_ID] == "unit_tests"
        assert parsed["level"] == "INFO"


class TestJsonFormatter:
    def test_plain_message_records_still_format_as_json(self) -> None:
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="x",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="plain message",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(formatter.format(record))
        assert parsed["message"] == "plain message"
        assert parsed["level"] == "INFO"
