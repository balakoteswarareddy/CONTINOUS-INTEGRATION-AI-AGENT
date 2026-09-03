"""Load and validate the versioned governance catalog (Batch 1, Task C).

Every human-authored YAML file under ``governance/catalog/`` is validated
against its JSON Schema in ``governance/schemas/`` at load time — fail fast,
fail closed (CI-Agent Production Architecture Report, Section 7 trust
boundaries). The loader returns plain ``dict`` payloads; compiling them into
PolicySpec instances is the job of a later batch (Policy Engine).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

SCHEMAS_DIR: Path = Path(__file__).resolve().parent / "schemas"
CATALOG_DIR: Path = Path(__file__).resolve().parent / "catalog"
POLICIES_DIR: Path = CATALOG_DIR / "policies"

POLICY_FILE_NAMES: tuple[str, ...] = (
    "identity_policy",
    "tool_policy",
    "security_policy",
    "build_policy",
    "artifact_policy",
    "approval_policy",
    "ai_policy",
)

CATALOG_FILE_NAMES: tuple[str, ...] = (
    "intake_schema.yaml",
    "data_classification.yaml",
    "provider_matrix.yaml",
)

_SCHEMA_FOR_CATALOG_FILE: dict[str, str] = {
    "intake_schema.yaml": "intake_schema",
    "data_classification.yaml": "data_classification",
    "provider_matrix.yaml": "provider_matrix",
}


class GovernanceError(Exception):
    """Base class for all governance catalog errors."""


class GovernanceLoadError(GovernanceError):
    """A governance file is missing, unreadable, not YAML, or of unknown name."""


class GovernanceValidationError(GovernanceError):
    """A governance file failed validation against its JSON Schema."""


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    """Read a YAML file and return its top-level mapping."""
    if not path.is_file():
        raise GovernanceLoadError(f"Governance file not found: {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise GovernanceLoadError(f"Could not parse YAML file {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise GovernanceLoadError(
            f"Expected a top-level mapping in {path}; got {type(payload).__name__}"
        )
    return payload


def _load_json_schema(schema_name: str) -> dict[str, Any]:
    """Read a JSON Schema definition from ``governance/schemas/``."""
    path = SCHEMAS_DIR / f"{schema_name}.schema.json"
    if not path.is_file():
        raise GovernanceLoadError(f"JSON Schema not found: {path}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise GovernanceLoadError(f"Expected a top-level object in JSON Schema {path}")
    return schema


def _format_error(error: jsonschema.exceptions.ValidationError) -> str:
    """Render one jsonschema validation error as an indented, path-qualified line."""
    path_text = "/".join(str(part) for part in error.absolute_path) or "<root>"
    return f"  - at {path_text}: {error.message}"


def validate_against_schema(payload: dict[str, Any], *, schema_name: str, label: str) -> None:
    """Validate ``payload`` against the named JSON Schema.

    Raises :class:`GovernanceValidationError` with every violation listed if
    the payload does not conform.
    """
    schema = _load_json_schema(schema_name)
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda err: list(err.absolute_path))
    if errors:
        details = "\n".join(_format_error(error) for error in errors)
        raise GovernanceValidationError(f"Governance validation failed for {label}:\n{details}")


def _load_validated(file_name: str, schema_name: str, directory: Path) -> dict[str, Any]:
    payload = _load_yaml_mapping(directory / file_name)
    validate_against_schema(payload, schema_name=schema_name, label=file_name)
    return payload


def load_intake_schema() -> dict[str, Any]:
    """Load ``catalog/intake_schema.yaml`` — the intake questionnaire (Report Section 14)."""
    return _load_validated("intake_schema.yaml", "intake_schema", CATALOG_DIR)


def load_data_classification() -> dict[str, Any]:
    """Load ``catalog/data_classification.yaml`` — Agent -> LLM data rules (Report Section 7.1)."""
    return _load_validated("data_classification.yaml", "data_classification", CATALOG_DIR)


def load_provider_matrix() -> dict[str, Any]:
    """Load ``catalog/provider_matrix.yaml`` — supported provider matrix."""
    return _load_validated("provider_matrix.yaml", "provider_matrix", CATALOG_DIR)


def load_policy_file(name: str) -> dict[str, Any]:
    """Load one policy-family file from ``catalog/policies/`` (Report Section 6).

    ``name`` may be given with or without the ``.yaml`` suffix (e.g. ``"security_policy"``).
    Raises :class:`GovernanceLoadError` for unknown names.
    """
    base_name = name.removesuffix(".yaml")
    if base_name not in POLICY_FILE_NAMES:
        raise GovernanceLoadError(
            f"Unknown policy file {name!r}; expected one of: {', '.join(POLICY_FILE_NAMES)}"
        )
    return _load_validated(f"{base_name}.yaml", "policy_file", POLICIES_DIR)


def load_all_policy_files() -> dict[str, dict[str, Any]]:
    """Load and validate all seven policy-family files, keyed by name."""
    return {name: load_policy_file(name) for name in POLICY_FILE_NAMES}


def load_org_policy_version() -> str:
    """Return the single governed policy version shared by all 7 policy files.

    All family files must declare the SAME ``policy_version`` — a mixed-version
    catalog is a governance error and fails loudly (used e.g. to pin
    ``ProjectProfile.policy_version_pinned``).
    """
    loaded = load_all_policy_files()
    versions = {str(data["policy_version"]) for data in loaded.values()}
    if len(versions) != 1:
        detail = ", ".join(
            f"{name}={data['policy_version']}" for name, data in sorted(loaded.items())
        )
        raise GovernanceError(f"Policy family files disagree on policy_version: {detail}")
    return versions.pop()


def load_all_governance_files() -> dict[str, dict[str, Any]]:
    """Load and validate every governance file, keyed by repo-relative-style label."""
    loaded: dict[str, dict[str, Any]] = {}
    for file_name in CATALOG_FILE_NAMES:
        schema_name = _SCHEMA_FOR_CATALOG_FILE[file_name]
        loaded[f"catalog/{file_name}"] = _load_validated(file_name, schema_name, CATALOG_DIR)
    for name in POLICY_FILE_NAMES:
        loaded[f"catalog/policies/{name}.yaml"] = load_policy_file(name)
    return loaded
