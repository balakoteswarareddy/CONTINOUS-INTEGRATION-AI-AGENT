"""Unit tests: JSON Schemas reject malformed governance payloads (Batch 1, Task C)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from ci_agent.governance import GovernanceValidationError, loader

REPO_ROOT = Path(__file__).resolve().parents[3]
VALIDATE_SCRIPT = REPO_ROOT / "scripts" / "validate_governance.py"


def validate(payload: dict, schema_name: str) -> None:
    loader.validate_against_schema(payload, schema_name=schema_name, label="test-payload")


class TestIntakeSchemaValidation:
    def test_valid_payload_passes(self) -> None:
        validate(loader.load_intake_schema(), "intake_schema")  # must not raise

    def test_missing_sections_rejected(self) -> None:
        with pytest.raises(GovernanceValidationError, match="sections"):
            validate({"version": "1.0.0"}, "intake_schema")

    def test_enum_question_without_options_rejected(self) -> None:
        payload = {
            "version": "1.0.0",
            "sections": [
                {
                    "id": "project_classification",
                    "questions": [{"id": "business_criticality", "type": "enum", "required": True}],
                }
            ],
        }
        with pytest.raises(GovernanceValidationError, match="options"):
            validate(payload, "intake_schema")

    def test_question_without_required_flag_rejected(self) -> None:
        payload = {
            "version": "1.0.0",
            "sections": [
                {
                    "id": "slos",
                    "questions": [{"id": "pipeline_duration_target_minutes", "type": "integer"}],
                }
            ],
        }
        with pytest.raises(GovernanceValidationError, match="required"):
            validate(payload, "intake_schema")

    def test_unknown_question_type_rejected(self) -> None:
        payload = {
            "version": "1.0.0",
            "sections": [
                {
                    "id": "slos",
                    "questions": [
                        {
                            "id": "weird",
                            "type": "crystalline",
                            "required": True,
                            "options": ["a", "b"],
                        }
                    ],
                }
            ],
        }
        with pytest.raises(GovernanceValidationError, match="type"):
            validate(payload, "intake_schema")


class TestPolicyFileSchemaValidation:
    def test_valid_payload_passes(self) -> None:
        validate(loader.load_policy_file("security_policy"), "policy_file")  # must not raise

    def test_missing_policy_version_rejected(self) -> None:
        payload = loader.load_policy_file("security_policy")
        del payload["policy_version"]
        with pytest.raises(GovernanceValidationError, match="policy_version"):
            validate(payload, "policy_file")

    def test_unknown_field_rejected(self) -> None:
        payload = loader.load_policy_file("identity_policy")
        payload["root_access"] = True
        with pytest.raises(GovernanceValidationError, match="root_access"):
            validate(payload, "policy_file")

    def test_mixed_families_rejected(self) -> None:
        """A file must contain exactly ONE policy family body."""
        payload = loader.load_policy_file("identity_policy")
        payload.update(loader.load_policy_file("security_policy"))
        with pytest.raises(GovernanceValidationError, match="valid under each of"):
            validate(payload, "policy_file")

    def test_invalid_severity_threshold_key_rejected(self) -> None:
        payload = loader.load_policy_file("security_policy")
        payload["severity_thresholds"]["blocker"] = 0
        with pytest.raises(GovernanceValidationError, match="'blocker' was unexpected"):
            validate(payload, "policy_file")

    def test_non_boolean_flag_rejected(self) -> None:
        payload = loader.load_policy_file("security_policy")
        payload["require_secret_scan"] = "yes-please"
        with pytest.raises(GovernanceValidationError, match="require_secret_scan"):
            validate(payload, "policy_file")

    def test_bad_sbom_format_rejected(self) -> None:
        payload = loader.load_policy_file("artifact_policy")
        payload["sbom_format"] = "pdf"
        with pytest.raises(GovernanceValidationError, match="sbom_format"):
            validate(payload, "policy_file")

    def test_invalid_risk_tier_rejected(self) -> None:
        payload = loader.load_policy_file("approval_policy")
        payload["require_human_approval_for"] = ["cosmic"]
        with pytest.raises(GovernanceValidationError, match="require_human_approval_for"):
            validate(payload, "policy_file")


class TestDataClassificationSchemaValidation:
    def test_valid_payload_passes(self) -> None:
        validate(loader.load_data_classification(), "data_classification")  # must not raise

    def test_unknown_level_name_rejected(self) -> None:
        payload = loader.load_data_classification()
        payload["levels"].append({"name": "top_secret", "can_send_to_ai_model": False})
        with pytest.raises(GovernanceValidationError, match="name"):
            validate(payload, "data_classification")

    def test_missing_canonical_level_rejected(self) -> None:
        payload = loader.load_data_classification()
        payload["levels"] = [lvl for lvl in payload["levels"] if lvl["name"] != "restricted"]
        with pytest.raises(GovernanceValidationError):
            validate(payload, "data_classification")

    def test_missing_ai_rule_rejected(self) -> None:
        payload = loader.load_data_classification()
        del payload["levels"][0]["can_send_to_ai_model"]
        with pytest.raises(GovernanceValidationError, match="can_send_to_ai_model"):
            validate(payload, "data_classification")


class TestProviderMatrixSchemaValidation:
    def test_valid_payload_passes(self) -> None:
        validate(loader.load_provider_matrix(), "provider_matrix")  # must not raise

    def test_missing_key_rejected(self) -> None:
        payload = loader.load_provider_matrix()
        del payload["runner_providers"]
        with pytest.raises(GovernanceValidationError, match="runner_providers"):
            validate(payload, "provider_matrix")

    def test_non_list_value_rejected(self) -> None:
        payload = loader.load_provider_matrix()
        payload["scm_providers"] = "github"
        with pytest.raises(GovernanceValidationError, match="scm_providers"):
            validate(payload, "provider_matrix")


class TestValidateGovernanceCli:
    def test_cli_exits_zero_and_reports_all_ten_files(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATE_SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.count("PASS") == 10  # 3 catalog files + 7 policy files
        assert "FAIL" not in result.stdout
        assert "10/10 governance files valid." in result.stdout
