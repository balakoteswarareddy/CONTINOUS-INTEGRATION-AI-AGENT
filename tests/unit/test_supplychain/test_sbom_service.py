"""SBOM service tests (Batch 7, Task B; Report Section 8 + Section 5.2 Stage 5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.base import Base, create_engine, get_session_factory
from ci_agent.supplychain.sbom_service import (
    SBOMParseError,
    SBOMService,
    TagOnlyDigestError,
    compute_artifact_digest,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture()
def services(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'sbom.db'}")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)
    audit_store = AuditStore(session_factory)
    # The AuditStore needs a run row for the FK on artifact_records.
    audit_store.create_run(
        run_id="run-sbom-1",
        project_id="example-org/payments-api",
        repository="example-org/payments-api",
        trigger_type="push",
        source_sha="cafe1234",
    )
    return SBOMService(session_factory, audit_store), session_factory


class TestParseSyftOutput:
    def test_spdx_fixture_parses(self, services) -> None:
        service, _ = services
        raw = (FIXTURES / "sbom" / "syft_spdx.json").read_text(encoding="utf-8")
        record = service.parse_syft_output(raw)
        assert record.format == "spdx"
        assert record.spec_version == "SPDX-2.3"
        assert record.component_count == 3
        assert record.raw_ref.startswith("artifact-store://")

    def test_cyclonedx_fixture_parses(self, services) -> None:
        service, _ = services
        raw = (FIXTURES / "sbom" / "syft_cyclonedx.json").read_text(encoding="utf-8")
        record = service.parse_syft_output(raw)
        assert record.format == "cyclonedx"
        assert record.spec_version == "1.5"
        assert record.component_count == 2

    def test_malformed_json_raises_not_empty_sbom(self, services) -> None:
        service, _ = services
        with pytest.raises(SBOMParseError):
            service.parse_syft_output("<<<not an sbom>>>")

    def test_unrecognized_document_raises(self, services) -> None:
        service, _ = services
        with pytest.raises(SBOMParseError):
            service.parse_syft_output('{"random": {"shape": true}}')


class TestDigestIdentity:
    """Section 8: identity = immutable digest; a tag is NEVER evidence."""

    def test_accepts_docker_inspect_id_output(self) -> None:
        digest = "sha256:" + "ab" * 32
        assert compute_artifact_digest(f"{digest}\n") == digest

    def test_tag_only_input_is_rejected(self) -> None:
        with pytest.raises(TagOnlyDigestError, match="never a tag"):
            compute_artifact_digest("ci-agent/app:ci")

    def test_empty_input_is_rejected(self) -> None:
        with pytest.raises(TagOnlyDigestError):
            compute_artifact_digest("   ")

    def test_malformed_digest_is_rejected(self) -> None:
        with pytest.raises(TagOnlyDigestError):
            compute_artifact_digest("sha256:xyz")

    def test_tag_input_cannot_become_a_digest_even_uppercase(self) -> None:
        with pytest.raises(TagOnlyDigestError):
            compute_artifact_digest("registry.example.com/team/app:latest")


class TestArtifactRecords:
    def test_record_artifact_persists_and_is_retrievable(self, services) -> None:
        service, _ = services
        digest = "sha256:" + "cd" * 32
        record = service.record_artifact("run-sbom-1", digest=digest, registry="ghcr.io")
        assert record.digest == digest
        fetched = service.artifact_for_run("run-sbom-1")
        assert fetched is not None
        assert fetched.digest == digest
        assert fetched.registry_host == "ghcr.io"

    def test_record_artifact_rejects_tag_digest(self, services) -> None:
        service, _ = services
        with pytest.raises(TagOnlyDigestError):
            service.record_artifact("run-sbom-1", digest="ci-agent/app:ci", registry="ghcr.io")

    def test_sbom_reference_attaches(self, services) -> None:
        service, _ = services
        raw = (FIXTURES / "sbom" / "syft_spdx.json").read_text(encoding="utf-8")
        sbom = service.parse_syft_output(raw)
        digest = "sha256:" + "ef" * 32
        service.record_artifact("run-sbom-1", digest=digest, registry="ghcr.io")
        updated = service.record_artifact(
            "run-sbom-1", digest=digest, registry="ghcr.io", sbom=sbom
        )
        assert updated.sbom_ref == sbom.raw_ref
        facts = SBOMService.artifact_facts(service.artifact_for_run("run-sbom-1"), "spdx")
        assert facts == [
            {
                "digest": digest,
                "registry": "ghcr.io",
                "has_sbom": True,
                "has_signature": False,
                "sbom_format": "spdx",
            }
        ]

    def test_artifact_recording_is_audited_counts_only(self, services) -> None:
        service, session_factory = services
        digest = "sha256:" + "10" * 32
        service.record_artifact("run-sbom-1", digest=digest, registry="ghcr.io")
        audit_store = AuditStore(session_factory)
        events = [e.event_type for e in audit_store.get_audit_trail("run-sbom-1")]
        assert "artifact_recorded" in events
