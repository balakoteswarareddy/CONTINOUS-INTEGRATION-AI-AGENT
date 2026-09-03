"""Supply-chain evidence records (Batch 7; Report Section 8).

These Pydantic models are the parse-side currency of the supply-chain
services; each aligns to the Batch 1 EvidenceModel shapes:

* :class:`SBOMRecord` -> ``ArtifactRef.sbom_ref`` (Section 8 SBOM row)
* :class:`SignatureRecord` -> ``ArtifactRef.signature_ref`` (Section 8
  signature + verification rows)
* :class:`ProvenanceRecord` -> ``EvidenceModel.attestations`` (Section 8
  provenance row; in-toto/SLSA-style attestation reference)

Pointers, never blobs: the full SBOM/attestation artifacts live in the
evidence store; these records keep references + integrity hashes so the
EvidenceModel stays small and auditable.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class SBOMRecord(BaseModel):
    """Parsed SBOM summary for one artifact (Section 8 — SBOM row)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # "spdx" or "cyclonedx" — BOTH supported (Section 8 "use an approved
    # format such as SPDX or CycloneDX"; Section 12 SBOM-adapter neutrality).
    format: str
    component_count: int = Field(ge=0)
    # Pointer to the stored full SBOM document (artifact store reference).
    raw_ref: str
    spec_version: str | None = None


class SignatureRecord(BaseModel):
    """A recorded signature reference for one artifact digest (Section 8).

    The signing KEY never passes through here (keyless: there is none;
    test-key fallback: the key lives only in the runner environment) — this
    record carries reference pointers + integrity hash of the signature file.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_digest: str
    signature_ref: str
    bundle_ref: str | None = None
    # True when produced via keyless OIDC signing (Section 7.2 preference).
    keyless: bool = False
    # sha256 of the signature file contents (integrity of the reference).
    signature_sha256: str
    signed_at: datetime = Field(default_factory=_utcnow)


class ProvenanceRecord(BaseModel):
    """A recorded in-toto/SLSA provenance attestation (Section 8).

    ``attestation_sha256`` pins the attestation content; ``subject_digest``
    is verified to EQUAL the artifact digest at record time — a provenance
    document for any other digest is rejected (tamper detection, tested).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_digest: str
    attestation_ref: str
    predicate_type: str
    attestation_sha256: str
    subject_digest: str
    recorded_at: datetime = Field(default_factory=_utcnow)


__all__ = ["ProvenanceRecord", "SBOMRecord", "SignatureRecord"]
