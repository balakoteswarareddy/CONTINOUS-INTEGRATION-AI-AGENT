"""TelemetryEmitter: structured JSON log emission (Batch 8, Task E).

Emits one JSON object per event via Python's stdlib ``logging``, using a JSON
formatter and the OTel-aligned field names from
:mod:`ci_agent.telemetry.conventions` — never free-form strings for the
convention-covered fields.

HARD RELIABILITY CONTRACT (Report Section 10): the emitter must NEVER raise.
Telemetry is observability, not a control-plane dependency — a broken
formatter, closed stream or exploding model must never take down run
orchestration. Every emission is wrapped; on internal error a reduced
error-indicator line is attempted and the exception is swallowed either way.
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC, datetime

from ci_agent.telemetry import conventions
from ci_agent.telemetry.pipeline_event import PipelineRunEvent, StageEvent, WorkerEvent

DEFAULT_LOGGER_NAME = "ci_agent.telemetry"


class JsonFormatter(logging.Formatter):
    """Format a LogRecord as a single JSON object line.

    When ``record.msg`` is already a dict (the emitter's contract), its keys
    are merged into the envelope — the emitted line is one flat JSON object,
    not JSON-in-JSON.
    """

    def format(self, record: logging.LogRecord) -> str:
        envelope: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
        }
        if isinstance(record.msg, dict):
            envelope.update(record.msg)
        else:  # pragma: no cover - defensive: plain messages pass through
            envelope["message"] = record.getMessage()
        return json.dumps(envelope, sort_keys=True, default=str)


class TelemetryEmitter:
    """Emit OTel-aligned pipeline/stage/worker events as JSON log lines.

    The emitter is a plain object (single instance per app, wired onto
    ``app.state``) so tests can inject a capturing logger. Field names for
    convention-covered values come from :mod:`conventions`; structural fields
    (``event``, ``event_type``, ``status``, timestamps) use stable plain
    names documented here.
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(DEFAULT_LOGGER_NAME)

    def emit_pipeline_run(self, event: PipelineRunEvent) -> None:
        """Emit a pipeline-run lifecycle event (never raises)."""
        payload: dict[str, object] = {
            "event": "pipeline_run",
            "event_type": event.event_type,
            conventions.CICD_PIPELINE_NAME: event.pipeline_name,
            conventions.CICD_PIPELINE_RUN_ID: event.run_id,
            conventions.CI_AGENT_RUN_ID: event.run_id,
            conventions.CI_AGENT_RUNNER: event.runner,
            "status": event.status.value,
            "started_at": event.started_at.isoformat() if event.started_at else None,
            "completed_at": event.completed_at.isoformat() if event.completed_at else None,
        }
        payload.update(event.attributes)
        self._emit(payload, "pipeline_run")

    def emit_stage(self, event: StageEvent) -> None:
        """Emit a stage (task) lifecycle event (never raises)."""
        payload: dict[str, object] = {
            "event": "stage",
            conventions.CICD_PIPELINE_RUN_ID: event.run_id,
            conventions.CI_AGENT_RUN_ID: event.run_id,
            conventions.CICD_PIPELINE_TASK_NAME: event.stage_id,
            conventions.CI_AGENT_STAGE_ID: event.stage_id,
            conventions.CICD_PIPELINE_TASK_TYPE: event.task_type,
            "status": event.status.value,
            "duration_ms": event.duration_ms,
            "exit_code": event.exit_code,
        }
        payload.update(event.attributes)
        self._emit(payload, "stage")

    def emit_worker(self, event: WorkerEvent) -> None:
        """Emit a runner-worker state event (never raises)."""
        payload: dict[str, object] = {
            "event": "worker",
            conventions.CICD_WORKER_ID: event.worker_id,
            conventions.CICD_WORKER_STATE: event.worker_state,
            conventions.CI_AGENT_RUNNER: event.runner,
        }
        payload.update(event.attributes)
        self._emit(payload, "worker")

    # ------------------------------------------------------------ internals

    def _emit(self, payload: dict[str, object], source_event: str) -> None:
        """Log one structured line; telemetry must never be a failure point.

        Section 10 (Reliability): an emitter failure is absorbed and reduced
        to a best-effort error-indicator line; the exception NEVER propagates
        into the control plane's request/orchestration path.
        """
        try:
            self._logger.info(payload)
        except Exception:
            # Even the error indicator failing must never raise (Section 10).
            with contextlib.suppress(Exception):
                self._logger.error(
                    {
                        "event": "telemetry_error",
                        "source_event": source_event,
                        "note": "emission failed; exception swallowed (Section 10)",
                    }
                )


__all__ = [
    "DEFAULT_LOGGER_NAME",
    "JsonFormatter",
    "TelemetryEmitter",
]
