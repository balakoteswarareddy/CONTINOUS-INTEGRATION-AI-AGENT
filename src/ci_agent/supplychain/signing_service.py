"""Signing / provenance service (Batch 7, Task C; Report Sections 7.2, 8).

Records cosign signature + provenance attestation REFERENCES for an artifact
digest (never key material — keyless signing has none; the test-key fallback
lives only in the runner environment) and exposes a REAL ``cosign verify``
wrapper for downstream consumers (Section 8 "Verification" row). Verification
shells out to the configured cosign binary via :class:`VerifyRunner`; a
missing binary or non-zero exit is ``False`` — verification is never faked
(no stub-True anywhere).

Signing decision (documented in NOTES.md): keyless OIDC is the governed
preference but is not feasible in the dev/test environment (no cluster OIDC
bridge), so the MVP signs with a runner-environment test key; flagged as a
pre-production hardening item.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.models import ArtifactRecord, ProvenanceRecordRow, SignatureRecordRow
from ci_agent.supplychain.models import ProvenanceRecord, SignatureRecord
from ci_agent.supplychain.sbom_service import compute_artifact_digest

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"

# Key-material markers that must NEVER appear in anything this service
# persists (belt-and-braces invariant, asserted in tests).
_KEY_MATERIAL_MARKERS: tuple[str, ...] = (
    "-----BEGIN",
    "ENV://COSIGN_KEY",
    "env://COSIGN_KEY",
    "COSIGN_KEY=",
)


class SigningParseError(ValueError):
    """Cosign output is not a recognizable signature/attestation envelope.

    Fail-closed: the publish gate sees ``has_signature=False`` and blocks —
    an unparseable signing result can never look like a signed artifact.
    """


class ProvenanceMismatchError(ValueError):
    """The provenance attestation's subject digest ≠ the artifact digest.

    A provenance document about ANY other artifact is a tamper indicator and
    is rejected outright (explicitly tested).
    """


@dataclass(frozen=True)
class CommandResult:
    """Exit status + output of one external verify command."""

    returncode: int
    stdout: str
    stderr: str


class VerifyRunner:
    """Runs the real cosign binary (overridable seam for tests only).

    The production path is ``subprocess.run([cosign_binary, ...])`` — a real
    external verification call. Tests inject a fake runner or, better, point
    ``cosign_binary`` at a small real script so the actual subprocess path is
    exercised end-to-end.
    """

    def __init__(self, cosign_binary: str = "cosign") -> None:
        self._binary = cosign_binary

    @property
    def binary_path(self) -> str:
        """Resolved binary path; empty string when not installed."""
        return shutil.which(self._binary) or ""

    def run(self, args: Sequence[str]) -> CommandResult:
        completed = subprocess.run(
            [self._binary, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class SigningService:
    """Record signature/provenance references and verify signatures."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        audit_store: AuditStore,
        sbom_service: Any,
        *,
        verify_runner: VerifyRunner | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit_store = audit_store
        self._sbom_service = sbom_service  # SBOMService: links ArtifactRecord
        self._verify_runner = verify_runner or VerifyRunner()

    # ------------------------------------------------------------- signatures

    def record_signature(
        self, artifact_digest: str, cosign_output: str, *, run_id: str | None = None
    ) -> SignatureRecord:
        """Parse a cosign signing result envelope and record the reference.

        Expected envelope (the compiled sign step uploads this JSON):
        ``{"signature_ref": "...", "bundle_ref": "...", "keyless": bool}``.
        Key material anywhere in the output raises — the agent never stores
        or logs key bytes. The record is PERSISTED (signature_records) and
        retrievable via :meth:`get_signature_records`.
        """
        for marker in _KEY_MATERIAL_MARKERS:
            if marker in cosign_output:
                raise SigningParseError(
                    "cosign output contains key material — refusing to record "
                    "(the agent never stores or logs signing keys)"
                )
        try:
            payload = json.loads(cosign_output)
        except json.JSONDecodeError as exc:
            raise SigningParseError(f"cosign output is not valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("signature_ref"), str):
            raise SigningParseError("cosign output has no signature_ref — not recordable")

        digest = compute_artifact_digest(artifact_digest)
        signature_ref = str(payload["signature_ref"])
        record = SignatureRecord(
            artifact_digest=digest,
            signature_ref=signature_ref,
            bundle_ref=(
                payload.get("bundle_ref") if isinstance(payload.get("bundle_ref"), str) else None
            ),
            keyless=bool(payload.get("keyless", False)),
            signature_sha256=hashlib.sha256(cosign_output.encode("utf-8")).hexdigest(),
        )
        self._sbom_service.link_signature(digest, signature_ref)
        with self._session_factory() as session:
            session.add(
                SignatureRecordRow(
                    run_id=run_id or "",
                    artifact_digest=digest,
                    signature_ref=record.signature_ref,
                    bundle_ref=record.bundle_ref,
                    keyless=record.keyless,
                    signature_sha256=record.signature_sha256,
                    signed_at=record.signed_at,
                )
            )
            session.commit()
        self._audit_store.append_event(
            f"signature:{digest}",
            "signature_recorded",
            # Reference pointers only — counts/refs, never signature bytes.
            {
                "artifact_digest": digest,
                "signature_ref": signature_ref,
                "keyless": record.keyless,
            },
        )
        return record

    # ------------------------------------------------------------ provenance

    def record_provenance(
        self, artifact_digest: str, provenance_attestation: str, *, run_id: str | None = None
    ) -> ProvenanceRecord:
        """Record an in-toto/SLSA provenance attestation reference.

        Validates the in-toto statement shape and that its subject digest
        EQUALS the artifact digest (tamper check). Stores the reference + a
        sha256 of the attestation content — never the attestation's embedded
        payloads.
        """
        try:
            statement = json.loads(provenance_attestation)
        except json.JSONDecodeError as exc:
            raise SigningParseError(f"provenance attestation is not valid JSON: {exc.msg}") from exc
        if not isinstance(statement, dict):
            raise SigningParseError("provenance attestation is not a JSON object")
        if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
            raise SigningParseError(
                f"provenance attestation _type must be {IN_TOTO_STATEMENT_TYPE!r}"
            )
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not subjects:
            raise SigningParseError("provenance attestation has no subject[]")
        digests = []
        for subject in subjects:
            if not isinstance(subject, dict) or not isinstance(subject.get("digest"), dict):
                raise SigningParseError("provenance subject has no digest map")
            sha = subject["digest"].get("sha256")
            if not isinstance(sha, str):
                raise SigningParseError("provenance subject digest has no sha256")
            digests.append(f"sha256:{sha}")

        digest = compute_artifact_digest(artifact_digest)
        if digest not in digests:
            raise ProvenanceMismatchError(
                f"provenance subject digest(s) {digests} do not match artifact {digest!r} "
                "— possible tampering; refusing to record"
            )

        predicate_type = str(statement.get("predicateType", SLSA_PROVENANCE_TYPE))
        attestation_sha256 = hashlib.sha256(provenance_attestation.encode("utf-8")).hexdigest()
        record = ProvenanceRecord(
            artifact_digest=digest,
            attestation_ref=f"artifact-store://attestations/{attestation_sha256}.json",
            predicate_type=predicate_type,
            attestation_sha256=attestation_sha256,
            subject_digest=digest,
        )
        with self._session_factory() as session:
            session.add(
                ProvenanceRecordRow(
                    run_id=run_id or "",
                    artifact_digest=digest,
                    attestation_ref=record.attestation_ref,
                    predicate_type=record.predicate_type,
                    attestation_sha256=record.attestation_sha256,
                    subject_digest=record.subject_digest,
                    recorded_at=record.recorded_at,
                )
            )
            session.commit()
        self._audit_store.append_event(
            f"provenance:{digest}",
            "provenance_recorded",
            {
                "artifact_digest": digest,
                "predicate_type": predicate_type,
                "attestation_sha256": attestation_sha256,
            },
        )
        return record

    # ------------------------------------------------------------ verification

    def verify_signature(self, artifact_digest: str) -> bool:
        """REAL cosign verification of the recorded signature.

        Runs ``cosign verify-blob --key <key_ref> --signature <sig_ref>
        --insecure-ignore-tlog <blob_ref>`` via the configured runner and
        returns ``returncode == 0``. Anything else — no recorded signature,
        cosign not installed, non-zero exit — is False (fail-closed; this
        function is never a stub returning True). The key reference comes
        from the runner environment configuration, never from the agent.
        """
        digest = compute_artifact_digest(artifact_digest)
        with self._session_factory() as session:
            record = (
                session.execute(
                    select(ArtifactRecord)
                    .where(
                        ArtifactRecord.digest == digest, ArtifactRecord.signature_ref.is_not(None)
                    )
                    .order_by(ArtifactRecord.id.desc())
                )
                .scalars()
                .first()
            )
        if record is None or not record.signature_ref:
            self._audit_store.append_event(
                f"signature:{digest}",
                "signature_verification_failed",
                {"reason": "no recorded signature"},
            )
            return False
        runner = self._verify_runner
        if not runner.binary_path:
            # cosign not installed in this environment: verification CANNOT
            # pass — fail closed (Section 18: no component publishes on an
            # unverifiable claim).
            self._audit_store.append_event(
                f"signature:{digest}",
                "signature_verification_failed",
                {"reason": "cosign binary not available"},
            )
            return False
        result = runner.run(
            [
                "verify-blob",
                "--key",
                "env://COSIGN_PUBLIC_KEY",
                "--signature",
                record.signature_ref,
                "--insecure-ignore-tlog",
                record.signature_ref + ".payload",
            ]
        )
        verified = result.returncode == 0
        self._audit_store.append_event(
            f"signature:{digest}",
            "signature_verified" if verified else "signature_verification_failed",
            {"returncode": result.returncode},
        )
        return verified

    # ------------------------------------------------------------- retrieval

    def get_signature_records(self, run_id: str) -> list[SignatureRecord]:
        """Persisted signature records for a run (Section 9 evidence)."""
        with self._session_factory() as session:
            rows = (
                session.execute(
                    select(SignatureRecordRow)
                    .where(SignatureRecordRow.run_id == run_id)
                    .order_by(SignatureRecordRow.id)
                )
                .scalars()
                .all()
            )
        return [
            SignatureRecord(
                artifact_digest=row.artifact_digest,
                signature_ref=row.signature_ref,
                bundle_ref=row.bundle_ref,
                keyless=row.keyless,
                signature_sha256=row.signature_sha256,
                signed_at=row.signed_at,
            )
            for row in rows
        ]

    def get_provenance_records(self, run_id: str) -> list[ProvenanceRecord]:
        """Persisted provenance records for a run (Section 9 evidence)."""
        with self._session_factory() as session:
            rows = (
                session.execute(
                    select(ProvenanceRecordRow)
                    .where(ProvenanceRecordRow.run_id == run_id)
                    .order_by(ProvenanceRecordRow.id)
                )
                .scalars()
                .all()
            )
        return [
            ProvenanceRecord(
                artifact_digest=row.artifact_digest,
                attestation_ref=row.attestation_ref,
                predicate_type=row.predicate_type,
                attestation_sha256=row.attestation_sha256,
                subject_digest=row.subject_digest,
                recorded_at=row.recorded_at,
            )
            for row in rows
        ]


__all__ = [
    "CommandResult",
    "ProvenanceMismatchError",
    "SigningParseError",
    "SigningService",
    "VerifyRunner",
]
