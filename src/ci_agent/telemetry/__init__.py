"""Normalized telemetry (Batch 8, Task E; Report Section 9 / ref [8]).

OTel CI/CD-aligned field vocabulary + Pydantic event models + a JSON log
emitter that can never raise. No opentelemetry-sdk dependency: the field
NAMES are the deliverable (portability), stdlib logging is the transport.
"""

from __future__ import annotations

from ci_agent.telemetry.emitter import DEFAULT_LOGGER_NAME, JsonFormatter, TelemetryEmitter
from ci_agent.telemetry.pipeline_event import PipelineRunEvent, StageEvent, WorkerEvent

__all__ = [
    "DEFAULT_LOGGER_NAME",
    "JsonFormatter",
    "PipelineRunEvent",
    "StageEvent",
    "TelemetryEmitter",
    "WorkerEvent",
]
