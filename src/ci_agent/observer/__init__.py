"""Execution Observer (Batch 4, Stage 10; Report Sections 4.2 and 10).

Collects stage state, exit codes, durations and log pointers back into
structured records — never inferring final state from free-form logs.
"""

from ci_agent.observer.execution_observer import ExecutionObserver, InvalidStageTransitionError
from ci_agent.observer.models import StageExecutionView

__all__ = ["ExecutionObserver", "InvalidStageTransitionError", "StageExecutionView"]
