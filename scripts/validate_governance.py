#!/usr/bin/env python3
"""Validate every governance YAML file against its JSON Schema.

Usage:
    python scripts/validate_governance.py

Prints one PASS/FAIL line per governance file (3 catalog files + 7 policy
family files) and a summary. Exit code is 0 when everything is valid, 1 when
any file fails.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from functools import partial
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPO_SRC = _REPO_ROOT / "src"
if (_REPO_SRC / "ci_agent").is_dir():
    # Allow running straight from a source checkout without installation.
    sys.path.insert(0, str(_REPO_SRC))

from ci_agent.governance import (
    POLICY_FILE_NAMES,
    GovernanceError,
    load_data_classification,
    load_intake_schema,
    load_policy_file,
    load_provider_matrix,
)


def main() -> int:
    checks: list[tuple[str, Callable[[], object]]] = [
        ("catalog/intake_schema.yaml", load_intake_schema),
        ("catalog/data_classification.yaml", load_data_classification),
        ("catalog/provider_matrix.yaml", load_provider_matrix),
    ]
    checks.extend(
        (f"catalog/policies/{name}.yaml", partial(load_policy_file, name))
        for name in POLICY_FILE_NAMES
    )

    failures: list[str] = []
    for label, load in checks:
        try:
            load()
        except GovernanceError as exc:
            failures.append(label)
            print(f"FAIL  {label}")
            print(f"      {exc}")
        else:
            print(f"PASS  {label}")

    total = len(checks)
    print(f"\n{total - len(failures)}/{total} governance files valid.")
    if failures:
        print("Failed files: " + ", ".join(failures))
        return 1
    print("All governance files are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
