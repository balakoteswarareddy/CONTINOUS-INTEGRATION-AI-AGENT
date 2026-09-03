"""Unit tests for the command template registry (Batch 4, Task A)."""

from __future__ import annotations

import pytest

from ci_agent.adapters.github_actions.command_template_registry import (
    CommandTemplateRegistry,
    UnknownCommandTemplateError,
    load_command_templates,
)


@pytest.fixture()
def registry() -> CommandTemplateRegistry:
    return CommandTemplateRegistry()


class TestAllowList:
    def test_known_ids_resolve(self, registry: CommandTemplateRegistry) -> None:
        assert registry.get_command("lint.ruff") == "ruff check ."
        assert registry.get_command("sast.bandit") == "bandit -r . -f json -o bandit-report.json"
        assert registry.get_command("tests.pytest") == "pytest --junitxml=results.xml"
        assert registry.get_command("scan.gitleaks").startswith("gitleaks detect")
        assert registry.get_command("scan.pip-audit") == "pip-audit -f json > pip-audit-report.json"

    def test_native_checkout_maps_to_none(self, registry: CommandTemplateRegistry) -> None:
        # checkout.default is handled natively by actions/checkout, not shell.
        assert registry.get_command("checkout.default") is None

    def test_unknown_id_raises(self, registry: CommandTemplateRegistry) -> None:
        with pytest.raises(UnknownCommandTemplateError, match=r"deploy\.prod"):
            registry.get_command("deploy.prod")

    def test_unknown_id_error_lists_known_ids(self, registry: CommandTemplateRegistry) -> None:
        with pytest.raises(UnknownCommandTemplateError, match=r"lint\.ruff"):
            registry.get_command("not-a-template")

    def test_all_batch3_template_ids_are_allow_listed(self) -> None:
        """Every external command_template_id in the Batch 3 templates must resolve.

        internal.* control-flow stages are orchestrated by the control plane
        and never consult the registry (compiler bypasses it for gates).
        """
        from ci_agent.adapters.github_actions.compiler import GATE_TOOL_PREFIX
        from ci_agent.planner.templates.template_registry import TemplateRegistry

        command_registry = CommandTemplateRegistry()
        for stack in TemplateRegistry().stacks:
            template = TemplateRegistry().get_template(stack)
            for stage in template["stages"]:
                if stage["tool_name"].startswith(GATE_TOOL_PREFIX):
                    continue
                assert stage["command_template_id"] in command_registry.known_ids, (
                    f"{stack}:{stage['stage_id']} references un-allow-listed "
                    f"{stage['command_template_id']}"
                )


class TestLoading:
    def test_shipped_file_loads(self) -> None:
        templates = load_command_templates()
        assert "checkout.default" in templates
        assert templates["lint.ruff"] == "ruff check ."

    def test_non_mapping_file_rejected(self, tmp_path) -> None:
        bad = tmp_path / "templates.yaml"
        bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="mapping"):
            load_command_templates(bad)

    def test_non_string_command_rejected(self, tmp_path) -> None:
        bad = tmp_path / "templates.yaml"
        bad.write_text('"bad.template": 42\n', encoding="utf-8")
        with pytest.raises(ValueError, match="must be a string or null"):
            load_command_templates(bad)


class TestPhaseBAllowList:
    """Batch 7 (Section 5.2): build/sbom/scan/sign/publish command templates."""

    def test_phase_b_ids_resolve_verbatim(self) -> None:
        assert (
            CommandTemplateRegistry().get_command("container.build")
            == "docker buildx build --load --tag ci-agent/app:ci --file Dockerfile . "
            "&& docker inspect --format '{{.Id}}' ci-agent/app:ci > image-digest.txt"
        )
        assert (
            CommandTemplateRegistry().get_command("sbom.syft")
            == "syft ci-agent/app:ci -o spdx-json=sbom.json"
        )
        assert (
            CommandTemplateRegistry().get_command("scan.trivy")
            == "trivy image --format json --output trivy-report.json ci-agent/app:ci"
        )
        assert "cosign sign" in CommandTemplateRegistry().get_command("sign.cosign")
        assert "docker push" in CommandTemplateRegistry().get_command("publish.oci")

    def test_build_and_integration_templates_per_stack(self) -> None:
        registry = CommandTemplateRegistry()
        assert registry.get_command("build.default.python").startswith("pytest --cov")
        assert "python -m build" in registry.get_command("build.default.python")
        assert registry.get_command("build.default.nodejs").startswith("npm ci")
        assert registry.get_command("test.integration.python").startswith(
            "pytest tests/integration"
        )
        assert "vitest run tests/integration" in registry.get_command("test.integration.nodejs")
