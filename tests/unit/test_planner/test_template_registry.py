"""Unit tests for the TemplateRegistry (Batch 3, Task B)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci_agent.planner.templates.template_registry import TemplateRegistry, UnknownStackError


@pytest.fixture()
def registry() -> TemplateRegistry:
    return TemplateRegistry()


class TestLoading:
    def test_shipped_templates_load(self, registry: TemplateRegistry) -> None:
        assert registry.stacks == ["nodejs", "python"]

    def test_python_template_structure(self, registry: TemplateRegistry) -> None:
        template = registry.get_template("python")

        assert template["stack"] == "python"
        stage_ids = [stage["stage_id"] for stage in template["stages"]]
        assert stage_ids == [
            "checkout",
            "format_lint",
            "sast",
            "unit_tests",
            "secret_scan",
            "dependency_scan",
            "policy_gate",
            "human_approval",
            "merge_decision",
        ]
        # Section 5.1 Phase A tool coverage.
        tools = {stage["tool_name"] for stage in template["stages"]}
        assert {"git", "ruff", "bandit", "pytest", "gitleaks", "pip-audit"} <= tools
        gates = {
            stage["tool_name"]
            for stage in template["stages"]
            if stage["tool_name"].startswith("internal.")
        }
        assert gates == {
            "internal.policy_gate",
            "internal.human_approval",
            "internal.merge_decision",
        }
        # Gate steps carry no container image (batch spec requirement).
        for stage in template["stages"]:
            if stage["tool_name"].startswith("internal."):
                assert stage["container_image"] is None

    def test_nodejs_template_structure(self, registry: TemplateRegistry) -> None:
        template = registry.get_template("nodejs")

        assert template["stack"] == "nodejs"
        tools = {stage["tool_name"] for stage in template["stages"]}
        assert {"git", "eslint", "semgrep", "vitest", "gitleaks", "npm-audit"} <= tools


class TestUnknownStack:
    def test_unknown_stack_raises_with_available_stacks(self, registry: TemplateRegistry) -> None:
        with pytest.raises(UnknownStackError, match=r"no stage template for stack .ruby."):
            registry.get_template("ruby")

    def test_no_silent_fallback_to_default_stack(self, registry: TemplateRegistry) -> None:
        """Requesting a missing stack must NEVER fall back to another template."""
        with pytest.raises(UnknownStackError):
            registry.get_template("RUST")


class TestSchemaValidation:
    def test_malformed_template_missing_required_field(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            # missing several required fields (command_template_id, ...)
            "stack: bad\nstages:\n  - stage_id: checkout\n    tool_name: git\n",
            encoding="utf-8",
        )

        with pytest.raises(Exception, match="command_template_id"):
            TemplateRegistry(templates_dir=tmp_path)

    def test_malformed_template_negative_timeout(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "stack: bad\n"
            "stages:\n"
            "  - stage_id: checkout\n"
            "    tool_name: git\n"
            "    tool_version: '2.43'\n"
            "    command_template_id: checkout.default\n"
            "    timeout_seconds: -5\n"
            "    retryable: true\n"
            "    max_retries: 1\n",
            encoding="utf-8",
        )

        with pytest.raises(Exception, match=r"timeout_seconds"):
            TemplateRegistry(templates_dir=tmp_path)

    def test_duplicate_stack_templates_rejected(self, tmp_path: Path) -> None:
        good = (
            "stack: dup\n"
            "stages:\n"
            "  - stage_id: checkout\n"
            "    tool_name: git\n"
            "    tool_version: '2.43'\n"
            "    command_template_id: checkout.default\n"
            "    timeout_seconds: 60\n"
            "    retryable: true\n"
            "    max_retries: 1\n"
        )
        (tmp_path / "one.yaml").write_text(good, encoding="utf-8")
        (tmp_path / "two.yaml").write_text(good, encoding="utf-8")

        with pytest.raises(ValueError, match="Duplicate stage template"):
            TemplateRegistry(templates_dir=tmp_path)

    def test_non_mapping_template_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "bad.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")

        with pytest.raises(ValueError, match="top-level mapping"):
            TemplateRegistry(templates_dir=tmp_path)
