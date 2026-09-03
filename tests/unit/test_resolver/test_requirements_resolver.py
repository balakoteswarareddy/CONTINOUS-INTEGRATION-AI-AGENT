"""Unit tests for the RequirementsResolver (Batch 2, Task C)."""

from __future__ import annotations

import copy
import pathlib
from typing import Any

import pytest

from ci_agent.core.models.common import RiskTier
from ci_agent.governance import load_intake_schema, load_org_policy_version
from ci_agent.resolver import (
    ConflictingRequirementsError,
    MissingRequirementsError,
    ProjectProfile,
    RequirementsResolver,
)

RESOLVER = RequirementsResolver()
INTAKE_SCHEMA = load_intake_schema()


def complete_answers() -> dict[str, Any]:
    """Flat answers covering every required question in the Batch 1 intake schema."""
    return {
        # project_classification
        "business_criticality": "high",
        "data_sensitivity": "confidential",
        "regulatory_scope": "PCI-DSS",
        "derived_risk_tier": "high",
        # repository_topology
        "repo_structure": "single_repo",
        "repository_url": "https://github.com/example-org/payments-api",
        "default_branch": "main",
        "protected_branches": ["main", "release/*"],
        # execution_locations
        "primary_execution_location": "github_hosted",
        "requires_dedicated_runners": False,
        # identity_model
        "identity_provider": "github_actions_oidc",
        "federated_identity_only": True,
        "allowed_identities": ["urn:ci:identity:payments-builder"],
        # network_policy
        "default_egress_posture": "allowlist",
        "allowed_egress_domains": ["pypi.org"],
        "requires_private_networking": False,
        # artifact_lifecycle
        "artifact_retention_days": 90,
        "promote_to_release_registry": True,
        "require_immutable_tags": True,
        "provenance_attestations_required": True,
        # exception_management
        "exception_process_owner": "platform-security",
        "max_exception_validity_days": 30,
        "waivers_allowed": True,
        # model_data_policy
        "default_data_classification": "internal",
        "ai_assistance_allowed": True,
        "approved_model_providers": [],
        "human_override_required": True,
        # slos
        "pipeline_duration_target_minutes": 20,
        "max_allowed_queue_minutes": 5,
        "ci_availability_target_percent": 99.5,
        # operational_ownership
        "owning_team": "payments-platform",
        "owning_team_channel": "#payments-ci",
        # runner
        "runner_os": "linux",
        "runner_architecture": "x86_64",
        "runner_provisioning": "autoscaled",
        # language_stack
        "primary_language": "python",
        # architecture
        "deployment_architecture": "microservices",
        "containerized_workload": True,
        "base_images": ["python:3.11-slim"],
        # security_tools
        "sast_tool": "bandit",
        "sca_tool": "pip-audit",
        "secret_scanning_tool": "gitleaks",
        "container_image_scanner": "trivy",
        "dast_tool": "",
        # secret_storage
        "secrets_provider": "hashicorp_vault",
        "short_lived_credentials_only": True,
        # coverage_requirements
        "minimum_coverage_percent": 80,
        "coverage_enforced_as_gate": True,
        # artifact_repository
        "artifact_registry_type": "github_packages",
        "sbom_required": True,
        "sbom_format": "spdx",
        "artifact_signing_required": True,
        # testing_strategy
        "unit_testing_required": True,
        "integration_testing_required": True,
    }


def schema_allowing_none_secret_storage() -> dict[str, Any]:
    """Intake schema variant where ``secrets_provider`` may legally be "none".

    The governed catalog's enum does not include "none", so Step 1 would
    reject it before the conflict rules run. The Batch 2 conflict rule
    ("restricted data + no secret storage") is still real policy: this variant
    exercises it for deployments whose intake schema does offer "none".
    """
    schema = copy.deepcopy(INTAKE_SCHEMA)
    for section in schema["sections"]:
        for question in section["questions"]:
            if question["id"] == "secrets_provider":
                question["options"] = [*question["options"], "none"]
    return schema


class TestValidResolution:
    def test_complete_intake_resolves_with_expected_profile(self) -> None:
        profile = RESOLVER.resolve(complete_answers(), INTAKE_SCHEMA, policy_version="1.0.0")

        assert isinstance(profile, ProjectProfile)
        assert profile.project_id == "example-org/payments-api"
        assert profile.business_criticality == "high"
        assert profile.data_sensitivity == "confidential"
        assert profile.risk_tier is RiskTier.HIGH  # from the documented matrix
        assert profile.repo_structure == "single_repo"
        assert profile.language_stack == "python"
        assert profile.runner == "linux"
        assert profile.security_tools == ["bandit", "pip-audit", "gitleaks", "trivy"]
        assert profile.secret_storage == "hashicorp_vault"
        assert profile.coverage_requirement == 80.0
        assert profile.artifact_repository == "github_packages"
        assert profile.testing_strategy == "unit+integration"
        assert profile.execution_location == "github_hosted"
        assert profile.policy_version_pinned == "1.0.0"

    def test_raw_answers_kept_verbatim(self) -> None:
        answers = complete_answers()

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")

        assert profile.raw_intake_answers == answers

    def test_nested_answers_are_normalized(self) -> None:
        answers = complete_answers()
        nested = {
            "project_classification": {
                "business_criticality": answers["business_criticality"],
                "data_sensitivity": answers["data_sensitivity"],
                "derived_risk_tier": answers["derived_risk_tier"],
            },
            "language_stack": {"primary_language": answers["primary_language"]},
        }
        # Replace the flat keys with a partially nested structure.
        flatten_keys = (
            "business_criticality",
            "data_sensitivity",
            "derived_risk_tier",
            "primary_language",
        )
        for key in flatten_keys:
            answers.pop(key)
        merged = {**nested, **answers}

        profile = RESOLVER.resolve(merged, INTAKE_SCHEMA, policy_version="1.0.0")

        assert profile.business_criticality == "high"
        assert profile.language_stack == "python"

    def test_policy_version_defaults_to_governed_catalog(self) -> None:
        profile = RESOLVER.resolve(complete_answers(), INTAKE_SCHEMA)

        assert profile.policy_version_pinned == load_org_policy_version()

    @pytest.mark.parametrize(
        ("criticality", "sensitivity", "expected"),
        [
            ("low", "public", RiskTier.LOW),
            ("low", "restricted", RiskTier.HIGH),
            ("medium", "confidential", RiskTier.HIGH),
            ("high", "restricted", RiskTier.REGULATED),
            ("critical", "confidential", RiskTier.REGULATED),
            ("critical", "public", RiskTier.MEDIUM),
        ],
    )
    def test_risk_tier_mapping_table(
        self, criticality: str, sensitivity: str, expected: RiskTier
    ) -> None:
        answers = complete_answers()
        answers["business_criticality"] = criticality
        answers["data_sensitivity"] = sensitivity
        answers["derived_risk_tier"] = expected.value

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")

        assert profile.risk_tier is expected


class TestMissingRequirements:
    def test_missing_required_fields_lists_all_at_once(self) -> None:
        answers = complete_answers()
        del answers["business_criticality"]
        del answers["data_sensitivity"]
        del answers["primary_language"]
        del answers["secrets_provider"]

        with pytest.raises(MissingRequirementsError) as excinfo:
            RESOLVER.resolve(answers, INTAKE_SCHEMA)

        message = str(excinfo.value)
        expected_missing = (
            "business_criticality",
            "data_sensitivity",
            "primary_language",
            "secrets_provider",
        )
        for missing in expected_missing:
            assert missing in message
        assert excinfo.value.problems == [
            "business_criticality",
            "data_sensitivity",
            "primary_language",
            "secrets_provider",
        ]

    def test_empty_string_counts_as_missing(self) -> None:
        answers = complete_answers()
        answers["owning_team"] = ""

        with pytest.raises(MissingRequirementsError, match="owning_team"):
            RESOLVER.resolve(answers, INTAKE_SCHEMA)

    def test_empty_list_is_missing_for_scalar_types_but_valid_for_string_list(self) -> None:
        answers = complete_answers()
        answers["base_images"] = []  # string_list -> valid deny-by-default answer

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")
        assert profile.project_id

        answers["default_egress_posture"] = []  # enum -> unanswered
        with pytest.raises(MissingRequirementsError, match="default_egress_posture"):
            RESOLVER.resolve(answers, INTAKE_SCHEMA)

    def test_optional_fields_may_be_absent(self) -> None:
        answers = complete_answers()
        del answers["regulatory_scope"]
        del answers["dast_tool"]
        answers.pop("escalation_contact", None)  # optional, not even in payload

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")

        assert profile.risk_tier is RiskTier.HIGH

    def test_invalid_enum_option_rejected(self) -> None:
        answers = complete_answers()
        answers["repo_structure"] = "spaghetti"

        with pytest.raises(MissingRequirementsError, match="invalid option 'spaghetti'"):
            RESOLVER.resolve(answers, INTAKE_SCHEMA)


class TestConflictRules:
    def test_confidential_without_security_tools_conflicts(self) -> None:
        answers = complete_answers()
        for key in ("sast_tool", "sca_tool", "secret_scanning_tool", "container_image_scanner"):
            answers[key] = ""

        with pytest.raises(ConflictingRequirementsError, match="security tool"):
            RESOLVER.resolve(answers, INTAKE_SCHEMA)

    def test_restricted_without_security_tools_conflicts(self) -> None:
        answers = complete_answers()
        answers["data_sensitivity"] = "restricted"
        answers["derived_risk_tier"] = "regulated"
        for key in ("sast_tool", "sca_tool", "secret_scanning_tool", "container_image_scanner"):
            answers[key] = ""

        with pytest.raises(ConflictingRequirementsError):
            RESOLVER.resolve(answers, INTAKE_SCHEMA)

    def test_restricted_without_secret_storage_conflicts(self) -> None:
        answers = complete_answers()
        answers["data_sensitivity"] = "restricted"
        answers["derived_risk_tier"] = "regulated"
        answers["secrets_provider"] = "none"

        with pytest.raises(ConflictingRequirementsError, match="secret storage"):
            RESOLVER.resolve(answers, schema_allowing_none_secret_storage())

    def test_all_conflicts_reported_at_once(self) -> None:
        answers = complete_answers()
        answers["data_sensitivity"] = "restricted"
        answers["derived_risk_tier"] = "regulated"
        answers["secrets_provider"] = "none"
        for key in ("sast_tool", "sca_tool", "secret_scanning_tool", "container_image_scanner"):
            answers[key] = ""

        with pytest.raises(ConflictingRequirementsError) as excinfo:
            RESOLVER.resolve(answers, schema_allowing_none_secret_storage())

        assert len(excinfo.value.conflicts) == 2

    def test_public_project_without_security_tools_is_fine(self) -> None:
        answers = complete_answers()
        answers["data_sensitivity"] = "public"
        answers["derived_risk_tier"] = "low"
        for key in ("sast_tool", "sca_tool", "secret_scanning_tool", "container_image_scanner"):
            answers[key] = ""

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")

        assert profile.security_tools == []


class TestWarningOnlyCases:
    def test_regulatory_scope_with_low_criticality_warns_without_raising(self) -> None:
        answers = complete_answers()
        answers["business_criticality"] = "low"
        answers["derived_risk_tier"] = "medium"

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")

        assert any("regulatory_scope" in warning for warning in profile.resolution_warnings)
        assert profile.risk_tier is RiskTier.MEDIUM  # computed, not the declared one

    def test_declared_risk_tier_mismatch_warns(self) -> None:
        answers = complete_answers()
        answers["derived_risk_tier"] = "low"  # mapping computes high for high/confidential

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")

        assert profile.risk_tier is RiskTier.HIGH
        assert any("declared risk tier" in warning for warning in profile.resolution_warnings)

    def test_no_mandatory_tests_warns(self) -> None:
        answers = complete_answers()
        answers["unit_testing_required"] = False
        answers["integration_testing_required"] = False

        profile = RESOLVER.resolve(answers, INTAKE_SCHEMA, policy_version="1.0.0")

        assert profile.testing_strategy == "none"
        assert any("no mandatory test stages" in warning for warning in profile.resolution_warnings)


class TestPurity:
    def test_resolver_does_not_mutate_inputs(self) -> None:
        answers = complete_answers()
        schema = load_intake_schema()
        answers_before = copy.deepcopy(answers)

        RESOLVER.resolve(answers, schema, policy_version="1.0.0")

        assert answers == answers_before

    def test_resolver_module_has_no_db_or_http_imports(self) -> None:
        import ci_agent.resolver.requirements_resolver as module

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        for forbidden in ("sqlalchemy", "fastapi", "httpx", "Session", "AuditStore"):
            assert forbidden not in source, f"resolver must stay pure; found {forbidden}"
