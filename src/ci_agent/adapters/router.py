"""Runner-adapter router — multi-runner scale (Batch 8, Task A; Section 12).

One :class:`RunnerAdapter`-shaped front door that delegates to the concrete
adapter chosen by the PROJECT's configured runner provider (Section 12:
"adapters, not provider-specific logic" — the orchestrators stay
provider-blind; routing is data-driven).

Failure isolation: each provider has its OWN circuit breaker. One runner
being down (its breaker open) raises
:class:`RunnerUnavailableError` for that project only — other projects on
other runners keep flowing (tested). Selection is fail-closed: an unknown
provider or a provider with no registered adapter raises loudly, never
falls back to a default (Section 7.3 allow-list discipline).
"""

from __future__ import annotations

from typing import Any

from ci_agent.adapters.base import (
    CompiledArtifact,
    DispatchRef,
    RunnerAdapter,
    RunnerStatusSnapshot,
)
from ci_agent.reliability.circuit_breaker import BreakerOpenError, CircuitBreaker

# ProjectProfile.execution_location -> runner provider. Explicit, reviewable
# mapping; values outside this table are a loud configuration error.
EXECUTION_LOCATION_TO_PROVIDER: dict[str, str] = {
    "github_hosted": "github_actions",
    "gitlab_hosted": "gitlab_ci",
    "jenkins_self_hosted": "jenkins",
}


class RunnerUnavailableError(RuntimeError):
    """The selected runner's breaker is OPEN (its provider is unhealthy)."""


class UnknownRunnerProviderError(ValueError):
    """The project's runner provider is not in the router's registry."""


class AdapterRouter(RunnerAdapter):
    """Route adapter calls by runner provider with per-runner breakers."""

    def __init__(
        self,
        adapters: dict[str, RunnerAdapter],
        resolve_provider: Any,  # Callable[[str], str] — (run_id) -> provider
        breakers: dict[str, CircuitBreaker] | None = None,
    ) -> None:
        self._adapters = dict(adapters)
        self._resolve_provider = resolve_provider
        self._breakers = breakers or {
            provider: CircuitBreaker(
                f"runner:{provider}", failure_threshold=5, recovery_timeout_seconds=60.0
            )
            for provider in adapters
        }

    # ----------------------------------------------------------------- helpers

    def _adapter_for(self, run_id: str) -> RunnerAdapter:
        provider = str(self._resolve_provider(run_id))
        adapter = self._adapters.get(provider)
        if adapter is None:
            raise UnknownRunnerProviderError(
                f"run {run_id!r} requests runner provider {provider!r}; "
                f"registered providers: {sorted(self._adapters)} — never falling "
                "back to another runner (fail-closed selection)"
            )
        return adapter

    def _call(self, run_id: str, provider: str, operation: Any, *args: Any) -> Any:
        breaker = self._breakers.get(provider)
        if breaker is None:
            return operation(*args)
        try:
            return breaker.call(lambda: operation(*args))
        except BreakerOpenError as exc:
            # Translate to the runner-domain failure: THIS provider is down;
            # other runners on the router are unaffected (isolation, tested).
            raise RunnerUnavailableError(
                f"runner provider {provider!r} is unavailable ({exc}); "
                "other runners are unaffected"
            ) from exc

    # ------------------------------------------------- RunnerAdapter interface

    def compile(self, plan: Any, metadata: dict[str, str] | None = None) -> CompiledArtifact:
        run_id = str(getattr(plan, "run_id", "") or "")
        provider = str(self._resolve_provider(run_id))
        adapter = self._adapter_for(run_id)
        result: CompiledArtifact = self._call(
            run_id, provider, lambda: adapter.compile(plan, metadata)
        )
        return result

    def dispatch(self, artifact: CompiledArtifact, run_id: str) -> DispatchRef:
        provider = str(self._resolve_provider(run_id))
        adapter = self._adapter_for(run_id)
        result: DispatchRef = self._call(run_id, provider, adapter.dispatch, artifact, run_id)
        if result.provider is None:
            result = result.model_copy(update={"provider": provider})
        return result

    def poll_status(self, dispatch_ref: DispatchRef) -> RunnerStatusSnapshot:
        run_id = dispatch_ref.run_id
        provider = str(self._resolve_provider(run_id))
        adapter = self._adapter_for(run_id)
        result: RunnerStatusSnapshot = self._call(
            run_id, provider, adapter.poll_status, dispatch_ref
        )
        return result

    def fetch_step_logs(self, dispatch_ref: DispatchRef, step_id: str) -> str:
        run_id = dispatch_ref.run_id
        provider = str(self._resolve_provider(run_id))
        adapter = self._adapter_for(run_id)
        result: str = self._call(run_id, provider, adapter.fetch_step_logs, dispatch_ref, step_id)
        return result

    # ---------------------------------------------------------- introspection

    def provider_for(self, run_id: str) -> str:
        """The provider selected for ``run_id`` (routing transparency/tests)."""
        return str(self._resolve_provider(run_id))

    def adapter_for(self, run_id: str) -> RunnerAdapter:
        return self._adapter_for(run_id)


__all__ = [
    "EXECUTION_LOCATION_TO_PROVIDER",
    "AdapterRouter",
    "RunnerUnavailableError",
    "UnknownRunnerProviderError",
]
