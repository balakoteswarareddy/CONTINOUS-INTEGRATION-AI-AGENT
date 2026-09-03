"""SBOM service (Batch 7, Task B; Report Section 8 + Section 5.2 Stage 5).

Parses Syft SBOM output (SPDX-json AND CycloneDX-json — Section 12 vendor
neutrality: an SBOM adapter, not a format mandate) into :class:`SBOMRecord`
summaries, computes/validates the artifact digest from ACTUAL build output,
and persists :class:`~ci_agent.db.models.ArtifactRecord` rows that feed
``EvidenceModel.artifacts`` (empty since Batch 1 — populated for real now).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.models import ArtifactRecord
from ci_agent.supplychain.models import SBOMRecord

# docker inspect --format '{{.Id}}' output / registry digest line:
# "sha256:<64 lowercase hex>".
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SBOMParseError(ValueError):
    """Syft output is not a recognizable SPDX/CycloneDX document.

    Raised instead of silently returning an "empty SBOM" — an unparseable
    SBOM must fail the artifact gate (has_sbom stays False), never look like
    a clean bill of materials.
    """


class TagOnlyDigestError(ValueError):
    """A mutable tag reference was offered where a content digest is required.

    Section 8: "Use immutable digest as the primary identity; do not treat
    tags alone as integrity evidence." Tags are conveniences, never identity
    (explicitly tested).
    """


def compute_artifact_digest(build_output_ref: str) -> str:
    """Extract and validate the immutable digest from real build output.

    Accepts exactly what the build produced: ``docker inspect --format
    '{{.Id}}'`` output or a buildx/registry digest line — i.e.
    ``sha256:<64 hex>`` (whitespace-tolerated, case-normalized). A tag-only
    reference raises :class:`TagOnlyDigestError`; this function can NEVER
    derive a digest from a tag (Section 8; explicitly tested).
    """
    candidate = (build_output_ref or "").strip()
    if not candidate:
        raise TagOnlyDigestError("empty build output — no digest available")
    if candidate.startswith("sha256:") and _DIGEST_RE.match(candidate):
        return candidate
    # A "name:tag" shaped string (contains ':' but no sha256 prefix) is
    # precisely the mutable-identity input this function must reject.
    raise TagOnlyDigestError(
        f"refusing to derive artifact identity from {candidate!r}: "
        "digest must come from actual build output (sha256:<hex>), never a tag"
    )


class SBOMService:
    """Parse Syft output, validate digests, persist artifact records."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        audit_store: AuditStore,
        raw_ref_factory: Callable[[str, str], str] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit_store = audit_store
        # Builds the stored-SBOM pointer from (run_id, content_hash). The
        # default encodes the artifact-store convention; tests may pin it.
        self._raw_ref_factory = raw_ref_factory or self._default_raw_ref

    @staticmethod
    def _default_raw_ref(run_id: str, content_hash: str) -> str:
        return f"artifact-store://runs/{run_id}/sbom.json#sha256={content_hash}"

    # ------------------------------------------------------------------ parse

    def parse_syft_output(self, raw_json: str, *, run_id: str = "") -> SBOMRecord:
        """Parse Syft output into an :class:`SBOMRecord` (SPDX or CycloneDX).

        ``run_id`` parametrizes the stored-document pointer. Raises
        :class:`SBOMParseError` for anything that is not a recognizable SBOM
        document — callers must treat that as a fail-closed incident (the
        artifact gate will block on missing SBOM), never as a clean scan.
        """
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise SBOMParseError(f"SBOM output is not valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise SBOMParseError("SBOM output is not a JSON object")

        bom_format = payload.get("bomFormat")
        spdx_version = payload.get("spdxVersion")
        if bom_format == "CycloneDX":
            components = payload.get("components", [])
            if not isinstance(components, list):
                raise SBOMParseError("CycloneDX document has a non-list components field")
            return SBOMRecord(
                format="cyclonedx",
                component_count=len(components),
                spec_version=str(payload.get("specVersion", "")) or None,
                raw_ref=self._raw_ref_factory(run_id, self._sha256(raw_json)),
            )
        if isinstance(spdx_version, str) and spdx_version.upper().startswith("SPDX"):
            packages = payload.get("packages", [])
            if not isinstance(packages, list):
                raise SBOMParseError("SPDX document has a non-list packages field")
            return SBOMRecord(
                format="spdx",
                component_count=len(packages),
                spec_version=spdx_version,
                raw_ref=self._raw_ref_factory(run_id, self._sha256(raw_json)),
            )
        raise SBOMParseError(
            "SBOM output is neither SPDX (spdxVersion) nor CycloneDX (bomFormat) — "
            "fail closed rather than record an unverifiable SBOM"
        )

    # --------------------------------------------------------------- registry

    def record_artifact(
        self,
        run_id: str,
        *,
        digest: str,
        registry: str,
        sbom: SBOMRecord | None = None,
    ) -> ArtifactRecord:
        """Persist (or update) the run's ArtifactRecord from REAL build output.

        ``digest`` MUST come from build output via
        :func:`compute_artifact_digest` — a tag raises before any write.
        """
        validated = compute_artifact_digest(digest)
        with self._session_factory() as session:
            record = session.execute(
                select(ArtifactRecord).where(ArtifactRecord.digest == validated)
            ).scalar_one_or_none()
            if record is None:
                record = ArtifactRecord(run_id=run_id, digest=validated, registry_host=registry)
                session.add(record)
            record.registry_host = registry
            if sbom is not None:
                record.sbom_ref = sbom.raw_ref
            session.commit()
            session.refresh(record)
            session.expunge(record)
        self._audit_store.append_event(
            run_id,
            "artifact_recorded",
            # Digest + registry + SBOM pointer only — never raw SBOM content.
            {"digest": record.digest, "registry": registry, "sbom_ref": record.sbom_ref},
        )
        return record

    def link_signature(self, digest: str, signature_ref: str) -> ArtifactRecord:
        """Attach a signature reference to the artifact record."""
        validated = compute_artifact_digest(digest)
        with self._session_factory() as session:
            record = session.execute(
                select(ArtifactRecord).where(ArtifactRecord.digest == validated)
            ).scalar_one_or_none()
            if record is None:
                raise LookupError(f"no ArtifactRecord for digest {validated!r}")
            record.signature_ref = signature_ref
            session.commit()
            session.refresh(record)
            session.expunge(record)
        return record

    def artifact_for_run(self, run_id: str) -> ArtifactRecord | None:
        """The run's artifact record, if one was recorded."""
        with self._session_factory() as session:
            record = (
                session.execute(
                    select(ArtifactRecord)
                    .where(ArtifactRecord.run_id == run_id)
                    .order_by(ArtifactRecord.id.desc())
                )
                .scalars()
                .first()
            )
            if record is not None:
                session.expunge(record)
            return record

    @staticmethod
    def _sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def artifact_facts(
        record: ArtifactRecord | None, sbom_format: str | None = None
    ) -> list[dict[str, Any]]:
        """Runtime facts shape consumed by artifact_policy.rego.

        ``sbom_format`` is the parsed SBOM's format when one was recorded
        (``None``/empty when there is no SBOM — the has_sbom rule handles
        that; the format-mismatch rule must not double-report).
        """
        if record is None:
            return []
        return [
            {
                "digest": record.digest,
                "registry": record.registry_host,
                "has_sbom": bool(record.sbom_ref),
                "has_signature": bool(record.signature_ref),
                "sbom_format": sbom_format or "",
            }
        ]


__all__ = [
    "SBOMParseError",
    "SBOMService",
    "TagOnlyDigestError",
    "compute_artifact_digest",
]
