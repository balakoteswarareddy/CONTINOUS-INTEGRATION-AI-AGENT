"""Signing/provenance service tests (Batch 7, Task C; Report Sections 7.2, 8).

The verify path is exercised against a REAL subprocess: the tests build a
small ``cosign`` stand-in script that genuinely verifies a sha256 digest of
the payload file it is handed — so "tampered artifact rejected" is a real
crypto check, not a scripted boolean.
"""

from __future__ import annotations

import hashlib
import json
import stat
import textwrap
from pathlib import Path

import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.supplychain.sbom_service import SBOMService, TagOnlyDigestError
from ci_agent.supplychain.signing_service import (
    ProvenanceMismatchError,
    SigningParseError,
    SigningService,
    VerifyRunner,
)

DIGEST = "sha256:" + "ab" * 32

BUNDLE = json.dumps({"signature_ref": "image.sig", "bundle_ref": "image.bundle", "keyless": False})

ATTESTATION = json.dumps(
    {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "ci-agent/app", "digest": {"sha256": "ab" * 32}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"builder": {"id": "ci-agent"}, "buildType": "docker"},
    }
)


@pytest.fixture()
def services(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'sign.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    audit_store.create_run(
        run_id="run-sign-1",
        project_id="example-org/payments-api",
        repository="example-org/payments-api",
        trigger_type="push",
        source_sha="cafe1234",
    )
    sbom_service = SBOMService(session_factory, audit_store)
    signing = SigningService(session_factory, audit_store, sbom_service)
    return signing, sbom_service, session_factory, audit_store


class TestRecordSignature:
    def test_signature_persists_and_is_retrievable(self, services) -> None:
        signing, sbom_service, _, _ = services
        sbom_service.record_artifact("run-sign-1", digest=DIGEST, registry="ghcr.io")
        record = signing.record_signature(DIGEST, BUNDLE, run_id="run-sign-1")
        assert record.signature_ref == "image.sig"
        assert record.keyless is False
        rows = signing.get_signature_records("run-sign-1")
        assert len(rows) == 1
        assert rows[0].signature_ref == "image.sig"
        # The ArtifactRecord is linked for the publish gate.
        artifact = sbom_service.artifact_for_run("run-sign-1")
        assert artifact is not None and artifact.signature_ref == "image.sig"

    def test_key_material_is_never_stored(self, services) -> None:
        signing, _, session_factory, _ = services
        with pytest.raises(SigningParseError, match="key material"):
            signing.record_signature(DIGEST, "{'key': '-----BEGIN PRIVATE KEY-----'}")
        # Nothing was persisted.
        assert signing.get_signature_records("run-sign-1") == []
        del session_factory

    def test_malformed_envelope_fails_closed(self, services) -> None:
        signing, _, _, _ = services
        with pytest.raises(SigningParseError):
            signing.record_signature(DIGEST, "not json at all")
        with pytest.raises(SigningParseError):
            signing.record_signature(DIGEST, json.dumps({"nope": True}))

    def test_tag_digest_rejected(self, services) -> None:
        signing, _, _, _ = services
        with pytest.raises(TagOnlyDigestError):
            signing.record_signature("ci-agent/app:ci", BUNDLE)


class TestRecordProvenance:
    def test_provenance_persists_and_is_retrievable(self, services) -> None:
        signing, _, _, _ = services
        record = signing.record_provenance(DIGEST, ATTESTATION, run_id="run-sign-1")
        assert record.subject_digest == DIGEST
        assert record.predicate_type == "https://slsa.dev/provenance/v1"
        rows = signing.get_provenance_records("run-sign-1")
        assert len(rows) == 1
        assert rows[0].attestation_sha256 == hashlib.sha256(ATTESTATION.encode("utf-8")).hexdigest()

    def test_tampered_subject_digest_is_rejected(self, services) -> None:
        signing, _, _, _ = services
        tampered = json.loads(ATTESTATION)
        tampered["subject"][0]["digest"]["sha256"] = "ff" * 32
        with pytest.raises(ProvenanceMismatchError, match="tampering"):
            signing.record_provenance(DIGEST, json.dumps(tampered))

    def test_malformed_attestation_rejected(self, services) -> None:
        signing, _, _, _ = services
        with pytest.raises(SigningParseError):
            signing.record_provenance(DIGEST, '{"_type": "wrong"}')


class TestVerifySignatureReal:
    """The wrapper shells out for real; a fake script does genuine sha256
    verification so the tampered case is a real digest mismatch."""

    @staticmethod
    def _install_fake_cosign(tmp_path: Path, trusted_digest: str) -> Path:
        """A tiny REAL verifier: hashes the payload file it is handed and
        compares against ``trusted_digest`` (sha256 of the trusted payload)."""
        script = tmp_path / "bin" / "cosign-verify"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(
            textwrap.dedent(f"""\
                #!/bin/sh
                # Minimal REAL verifier: compares sha256 of the payload file
                # (the last argv entry) against the trusted digest baked in.
                for arg in "$@"; do payload="$arg"; done
                actual="sha256:$(sha256sum "$payload" | cut -d' ' -f1)"
                if [ "$actual" = "{trusted_digest}" ]; then exit 0; fi
                echo "digest mismatch: $actual" >&2
                exit 1
                """),
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        return script

    @staticmethod
    def _digest_of(content: str) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()

    def test_verify_calls_cosign_and_accepts_valid(self, services, tmp_path: Path) -> None:
        signing, sbom_service, _, audit = services
        sbom_service.record_artifact("run-sign-1", digest=DIGEST, registry="ghcr.io")
        signing.record_signature(DIGEST, BUNDLE, run_id="run-sign-1")

        trusted_payload = "the-signed-payload-bytes"
        payload_path = tmp_path / "image.sig.payload"
        payload_path.write_text(trusted_payload, encoding="utf-8")
        # The verifier trusts the PAYLOAD's own sha256 (cosign signs the
        # payload bytes, not the image digest).
        script = self._install_fake_cosign(tmp_path, self._digest_of(trusted_payload))

        # Route the recorded signature_ref to the REAL payload file: the
        # verifier hashes whatever file the wrapper hands it.
        class Runner(VerifyRunner):
            @property
            def binary_path(self) -> str:
                return str(script)

            def run(self, args):
                # Replace the signature-ref-based payload path with the real
                # file, as the evidence store would on a real host.
                args = list(args)
                args[-1] = str(payload_path)
                return super().run(args)

        signing._verify_runner = Runner(str(script))
        assert signing.verify_signature(DIGEST) is True
        events = [e.event_type for e in audit.get_audit_trail(f"signature:{DIGEST}")]
        assert "signature_verified" in events

    def test_verify_rejects_tampered_artifact(self, services, tmp_path: Path) -> None:
        signing, sbom_service, _, audit = services
        sbom_service.record_artifact("run-sign-1", digest=DIGEST, registry="ghcr.io")
        signing.record_signature(DIGEST, BUNDLE, run_id="run-sign-1")

        trusted_payload = "the-signed-payload-bytes"
        payload_path = tmp_path / "image.sig.payload"
        payload_path.write_text("TAMPERED-BYTES", encoding="utf-8")
        script = self._install_fake_cosign(tmp_path, self._digest_of(trusted_payload))

        class Runner(VerifyRunner):
            @property
            def binary_path(self) -> str:
                return str(script)

            def run(self, args):
                args = list(args)
                args[-1] = str(payload_path)
                return super().run(args)

        signing._verify_runner = Runner(str(script))
        assert signing.verify_signature(DIGEST) is False
        events = [e.event_type for e in audit.get_audit_trail(f"signature:{DIGEST}")]
        assert "signature_verification_failed" in events

    def test_verify_fails_closed_without_recorded_signature(self, services) -> None:
        signing, _, _, _ = services
        assert signing.verify_signature(DIGEST) is False

    def test_verify_fails_closed_when_cosign_missing(self, services) -> None:
        signing, sbom_service, _, _ = services
        sbom_service.record_artifact("run-sign-1", digest=DIGEST, registry="ghcr.io")
        signing.record_signature(DIGEST, BUNDLE, run_id="run-sign-1")
        signing._verify_runner = VerifyRunner("definitely-not-installed-cosign")
        assert signing.verify_signature(DIGEST) is False
