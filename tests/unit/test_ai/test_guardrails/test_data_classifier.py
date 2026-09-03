"""DataClassifier tests (Batch 9, Task B)."""

from __future__ import annotations

import pytest

from ci_agent.ai.guardrails.data_classifier import DataClassifier
from ci_agent.core.models.policy_spec import AIPolicy


@pytest.fixture()
def classifier() -> DataClassifier:
    return DataClassifier()


class TestClassification:
    def test_private_key_is_restricted(self, classifier: DataClassifier) -> None:
        content = (
            "some context\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        )
        assert classifier.classify(content) == "restricted"

    def test_gitlab_token_is_restricted(self, classifier: DataClassifier) -> None:
        assert classifier.classify("token: glpat-AbCdEf123456789012345") == "restricted"

    def test_github_pat_is_restricted(self, classifier: DataClassifier) -> None:
        assert classifier.classify("leaked ghp_AbCdEf123456789012345") == "restricted"

    def test_openai_key_is_restricted(self, classifier: DataClassifier) -> None:
        assert classifier.classify("uses sk-AbCdEf123456789012345678") == "restricted"

    def test_aws_key_is_restricted(self, classifier: DataClassifier) -> None:
        assert classifier.classify("key AKIAIOSFODNN7EXAMPLE here") == "restricted"

    def test_env_var_assignment_is_restricted(self, classifier: DataClassifier) -> None:
        assert classifier.classify("DATABASE_URL=postgres://host/db") == "restricted"

    def test_bearer_header_is_restricted(self, classifier: DataClassifier) -> None:
        assert classifier.classify("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp") == (
            "restricted"
        )

    def test_source_code_is_confidential(self, classifier: DataClassifier) -> None:
        assert classifier.classify("def process_payment(amount):\n    pass") == "confidential"

    def test_import_line_is_confidential(self, classifier: DataClassifier) -> None:
        assert classifier.classify("from ci_agent.core import models") == "confidential"

    def test_email_is_confidential(self, classifier: DataClassifier) -> None:
        assert classifier.classify("contact jane.doe@example.com for details") == "confidential"

    def test_structured_log_lines_are_internal(self, classifier: DataClassifier) -> None:
        assert classifier.classify("2026-09-03T10:00:00Z ERROR ruff: unused import") == "internal"

    def test_json_is_internal(self, classifier: DataClassifier) -> None:
        assert classifier.classify('{"outcome": "pass", "count": 3}') == "internal"

    def test_plain_prose_is_public(self, classifier: DataClassifier) -> None:
        assert classifier.classify("The build finished and everything looks fine.") == "public"


class TestPermissions:
    def test_is_permitted_for_ai_follows_policy(self, classifier: DataClassifier) -> None:
        policy = AIPolicy(
            allowed_model_providers=["fake"],
            allowed_data_classification=["public"],
            require_human_override=True,
        )
        assert classifier.is_permitted_for_ai("public", policy) is True
        assert classifier.is_permitted_for_ai("internal", policy) is False
        assert classifier.is_permitted_for_ai("restricted", policy) is False


class TestContentBoundaries:
    def test_without_source_lines_strips_source_only(self, classifier: DataClassifier) -> None:
        snippet = "\n".join(
            [
                "ruff: warning: unused import on line 3",
                "def leaked_function():",
                "import os",
                "from ci_agent.core import models",
                "FAILED tests/test_payment.py::test_charge - AssertionError",
            ]
        )
        kept = classifier.without_source_lines(snippet)
        assert "ruff: warning: unused import on line 3" in kept
        assert "FAILED tests/test_payment.py::test_charge" in kept
        assert "def leaked_function" not in kept
        assert "import os" not in kept
        assert "from ci_agent.core import models" not in kept

    def test_exceeds_ceiling(self, classifier: DataClassifier) -> None:
        assert classifier.exceeds_ceiling("confidential", "internal") is True
        assert classifier.exceeds_ceiling("restricted", "internal") is True
        assert classifier.exceeds_ceiling("internal", "internal") is False
        assert classifier.exceeds_ceiling("public", "internal") is False
        assert classifier.exceeds_ceiling("restricted", "public") is True
