"""AdapterRouter: runner-name -> RunnerAdapter selection (Batch 8, Task C).

The architectural wiring that makes multi-runner real end-to-end: the
orchestrators hold ONE router and select the concrete adapter per run at plan
time, instead of being wired to a single GitHub Actions adapter.

Design decisions (documented in NOTES.md):

- **Router keys use the provider_matrix runner vocabulary**
  (``github_actions`` / ``gitlab_ci`` / ``jenkins``) — the same strings
  ``governance/catalog/provider_matrix.yaml`` lists under ``runner_providers``.
- **No silent fallback.** ``get_adapter`` raises :class:`UnknownRunnerError`
  for an unknown/unregistered runner — a run configured for a runner with no
  adapter fails LOUDLY at plan time (the orchestrators park it in ERROR),
  never silently proceeds with the wrong runner.
- **Deployment default runner.** ``ProjectProfile.runner`` carries the runner
  OS (``linux``/``windows``/``macos`` — the resolver maps the ``runner_os``
  intake question), NOT a platform name; until profiles carry an explicit
  platform field, the deployment's configured default runner
  (``CI_AGENT_DEFAULT_RUNNER``, default ``github_actions``) selects the
  platform. This is one explicit, documented selection rule — and if the
  DEFAULT itself is not registered, it still fails loudly rather than
  falling back further. When a profile runner value IS a registered platform
  name (future intake enrichment), it wins with zero changes here.
"""

from __future__ import annotations

from typing import Any

from ci_agent.adapters.base import RunnerAdapter
from ci_agent.adapters.errors import UnknownRunnerError

DEFAULT_RUNNER = "github_actions"


class AdapterRouter:
    """Select the right :class:`RunnerAdapter` for a run's runner name."""

    def __init__(
        self,
        adapters: dict[str, RunnerAdapter] | None = None,
        *,
        default_runner: str = DEFAULT_RUNNER,
    ) -> None:
        self._adapters: dict[str, RunnerAdapter] = dict(adapters or {})
        self._default_runner = default_runner

    # ------------------------------------------------------------------ public

    def register(self, runner: str, adapter: RunnerAdapter) -> None:
        """Register (or replace) the adapter for one runner name."""
        self._adapters[runner] = adapter

    @property
    def known_runners(self) -> list[str]:
        """Registered runner names (provider_matrix vocabulary), sorted."""
        return sorted(self._adapters)

    @property
    def default_runner(self) -> str:
        return self._default_runner

    def get_adapter(self, runner: str) -> RunnerAdapter:
        """Return the adapter for ``runner`` or raise :class:`UnknownRunnerError`.

        Never falls back: an unknown or unregistered runner is a hard,
        loud failure at the call site (plan time in the orchestrators).
        """
        adapter = self._adapters.get(runner)
        if adapter is None:
            raise UnknownRunnerError(
                f"no adapter registered for runner {runner!r}; "
                f"known runners: {', '.join(self.known_runners) or '(none)'}"
            )
        return adapter

    def adapter_for_profile(self, profile_runner: str | None) -> RunnerAdapter:
        """Select the adapter for a run, given the project profile's runner.

        The profile's ``runner`` field carries the runner OS today (see the
        module docstring); when it is NOT a registered platform name, the
        deployment's explicit default runner selects the platform. A missing
        default registration still raises :class:`UnknownRunnerError`.
        """
        if profile_runner and profile_runner in self._adapters:
            return self._adapters[profile_runner]
        return self.get_adapter(self._default_runner)

    # ------------------------------------------------------------ dunder/misc

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<AdapterRouter runners={self.known_runners!r} " f"default={self._default_runner!r}>"
        )


def select_runner_name(profile: Any) -> str | None:
    """Extract the profile's runner field as a plain string (or None)."""
    value = getattr(profile, "runner", None)
    return str(value) if value else None


__all__ = [
    "DEFAULT_RUNNER",
    "AdapterRouter",
    "select_runner_name",
]
