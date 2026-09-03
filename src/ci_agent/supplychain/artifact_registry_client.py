"""Artifact registry client (Batch 7; Section 6 Artifact family).

A deliberately THIN wrapper: the actual ``docker push`` runs inside the
compiled publish job; the control plane uses this client to validate the
configured publish target against the governed ``registry_allowlist``
BEFORE the publish gate, and to run a push itself when operating in a
control-plane-driven environment. Anything outside the allowlist is refused
before any command is constructed — never after.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence


class RegistryNotAllowedError(ValueError):
    """The publish target registry is not in the governed allowlist."""


class ArtifactRegistryClient:
    """Allowlist-gated OCI registry operations."""

    def __init__(
        self,
        registry_allowlist: Sequence[str],
        *,
        command_runner: Callable[[Sequence[str]], int] | None = None,
    ) -> None:
        self._allowlist = list(registry_allowlist)
        self._runner = command_runner or self._default_runner

    @staticmethod
    def _default_runner(argv: Sequence[str]) -> int:
        completed = subprocess.run(
            list(argv), capture_output=True, text=True, check=False, timeout=600
        )
        return completed.returncode

    def validate_target(self, registry: str) -> str:
        """Return ``registry`` if allowlisted; raise otherwise (pre-command)."""
        if registry not in self._allowlist:
            raise RegistryNotAllowedError(
                f"registry {registry!r} is not in the artifact policy allowlist "
                f"{self._allowlist} — publish refused before any command runs"
            )
        return registry

    def push(self, registry: str, repository: str, tag_or_digest: str) -> int:
        """Push a pre-built local image reference to an allowlisted registry."""
        self.validate_target(registry)
        reference = f"{registry}/{repository}:{tag_or_digest}"
        return self._runner(["docker", "push", reference])


__all__ = ["ArtifactRegistryClient", "RegistryNotAllowedError"]
