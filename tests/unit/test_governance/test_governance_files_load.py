"""Unit tests: governance catalog files load and validate via the loader (Batch 1, Task C)."""

from __future__ import annotations

import pytest

from ci_agent.governance import loader

EXPECTED_INTAKE_SECTION_IDS = {
    "project_classification",
    "repository_topology",
    "execution_locations",
    "identity_model",
    "network_policy",
    "artifact_lifecycle",
    "exception_management",
    "model_data_policy",
    "slos",
    "operational_ownership",
    "runner",
    "language_stack",
    "architecture",
    "security_tools",
    "secret_storage",
    "coverage_requirements",
    "artifact_repository",
    "testing_strategy",
}


class TestLoadIntakeSchema:
    def test_loads_with_version_and_all_sections(self) -> None:
        data = loader.load_intake_schema()

        assert data["version"] == "1.0.0"
        section_ids = {section["id"] for section in data["sections"]}
        assert section_ids == EXPECTED_INTAKE_SECTION_IDS

    @pytest.mark.parametrize(
        "section_id",
        sorted(EXPECTED_INTAKE_SECTION_IDS),
    )
    def test_every_section_has_questions(self, section_id: str) -> None:
        data = loader.load_intake_schema()

        section = next(s for s in data["sections"] if s["id"] == section_id)
        assert len(section["questions"]) >= 1
        for question in section["questions"]:
            assert "required" in question
            if question["type"] == "enum":
                assert len(question["options"]) >= 2


class TestLoadDataClassification:
    def test_loads_all_four_levels_with_expected_ai_rules(self) -> None:
        data = loader.load_data_classification()

        levels = {level["name"]: level for level in data["levels"]}
        assert set(levels) == {"public", "internal", "confidential", "restricted"}
        assert levels["public"]["can_send_to_ai_model"] is True
        assert levels["internal"]["can_send_to_ai_model"] is True
        assert levels["internal"]["conditions"] == ["must be normalized/anonymized"]
        assert levels["confidential"]["can_send_to_ai_model"] is False
        assert levels["restricted"]["can_send_to_ai_model"] is False


class TestLoadProviderMatrix:
    def test_loads_minimal_provider_matrix(self) -> None:
        data = loader.load_provider_matrix()

        assert data["version"] == "1.0.0"
        assert data["scm_providers"] == ["github"]
        assert data["runner_providers"] == ["github_actions"]
        assert data["security_tool_providers"] == []
        assert data["artifact_registries"] == []
        assert data["secrets_providers"] == []


class TestLoadPolicyFiles:
    @pytest.mark.parametrize("name", loader.POLICY_FILE_NAMES)
    def test_policy_file_loads_and_is_versioned(self, name: str) -> None:
        data = loader.load_policy_file(name)

        assert data["policy_version"] == "1.0.0"
        # Every shipped default must be non-trivially populated (never an empty file).
        assert len(data) >= 2

    def test_load_all_policy_files_returns_seven(self) -> None:
        loaded = loader.load_all_policy_files()
        assert set(loaded) == set(loader.POLICY_FILE_NAMES)

    def test_name_with_yaml_suffix_is_accepted(self) -> None:
        data = loader.load_policy_file("security_policy.yaml")
        assert "severity_thresholds" in data

    def test_unknown_policy_name_rejected(self) -> None:
        with pytest.raises(loader.GovernanceLoadError, match="Unknown policy file"):
            loader.load_policy_file("made_up_policy")

    def test_path_traversal_rejected(self) -> None:
        with pytest.raises(loader.GovernanceLoadError, match="Unknown policy file"):
            loader.load_policy_file("../intake_schema")


class TestMissingFileHandling:
    def test_missing_catalog_file_raises_clear_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.setattr(loader, "CATALOG_DIR", tmp_path)

        with pytest.raises(loader.GovernanceLoadError, match="not found"):
            loader.load_intake_schema()

    def test_non_mapping_yaml_raises_clear_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.setattr(loader, "CATALOG_DIR", tmp_path)
        (tmp_path / "intake_schema.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")

        with pytest.raises(loader.GovernanceLoadError, match="top-level mapping"):
            loader.load_intake_schema()

    def test_malformed_yaml_raises_clear_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        monkeypatch.setattr(loader, "CATALOG_DIR", tmp_path)
        (tmp_path / "intake_schema.yaml").write_text("version: [unclosed\n", encoding="utf-8")

        with pytest.raises(loader.GovernanceLoadError, match="Could not parse YAML"):
            loader.load_intake_schema()
