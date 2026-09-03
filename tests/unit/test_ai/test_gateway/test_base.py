"""ModelProvider abstract interface tests (Batch 9, Task A)."""

from __future__ import annotations

import inspect

import pytest

from ci_agent.ai.gateway.base import ModelProvider
from ci_agent.ai.models import AIRequest


class _Minimal(ModelProvider):
    """Smallest possible conforming provider."""

    def complete(self, request: AIRequest):  # type: ignore[override]
        raise NotImplementedError

    def is_available(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "minimal"


def test_cannot_instantiate_the_abstract_interface() -> None:
    with pytest.raises(TypeError):
        ModelProvider()  # type: ignore[abstract]


def test_concrete_subclass_instantiates() -> None:
    assert _Minimal().provider_name == "minimal"


def test_interface_surface_is_exactly_three_members() -> None:
    assert ModelProvider.__abstractmethods__ == frozenset(
        {"complete", "is_available", "provider_name"}
    )

    # The signatures are frozen contract (mirrors the conformance-suite
    # discipline from the runner adapters). Annotations render quoted
    # because of `from __future__ import annotations` — compare normalized.
    def _signature(name: str) -> str:
        return str(inspect.signature(getattr(ModelProvider, name))).replace("'", "")

    assert _signature("complete") == "(self, request: AIRequest) -> AIResponse"
    assert _signature("is_available") == "(self) -> bool"
