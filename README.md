# CI Agent

A **vendor-neutral Continuous Integration agent control plane**. Per the
architecture report's Executive Summary (Section 1), the CI Agent is not
another runner: it is a control plane that keeps a **vendor-neutral pipeline
specification as the internal source of truth**, compiles it into
runner-specific YAML or API calls, enforces **deterministic policy-as-code**
across seven policy families before anything executes, and records
**tamper-evident evidence** (findings, approvals, artifact digests,
attestations) for every run. GitHub Actions is merely the first adapter — the
models and governance catalog in this repository are deliberately
provider-neutral.

This repository currently contains **Batch 1**: the four canonical data models
(`PipelineSpec`, `PolicySpec`, `ExecutionPlan`, `EvidenceModel` — Report
Section 4.1) and the versioned governance catalog (policy families from
Section 6, intake questionnaire from Section 14), fully unit-tested. Nothing
executes yet: no database, no API, no runner adapters, no AI calls.

> This repository implements the architecture defined in
> `docs/architecture-reference.pdf`. Do not deviate without updating that
> document first.

## Repository layout

```
src/ci_agent/
├── core/models/        # Canonical data models (Section 4.1)
├── governance/         # Versioned governance catalog + JSON Schemas + loader
│   ├── catalog/        #   Human-authored YAML (intake, data classification,
│   │   └── policies/   #   provider matrix, and the 7 policy families)
│   └── schemas/        #   JSON Schemas validating the YAML at load time
└── config/             # Minimal env-driven settings (placeholder)
scripts/
└── validate_governance.py   # CLI: validates all governance files, non-zero exit on failure
tests/unit/             # pytest unit tests for models + governance
```

## Setup

Requires Python 3.11+.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run the tests

```bash
pytest -v
```

## Validate the governance catalog

```bash
python scripts/validate_governance.py
```

Prints a PASS/FAIL line for each of the 10 governance files (3 catalog files +
7 policy families) and exits non-zero if any file fails schema validation.

## Lint, format, type-check

```bash
ruff check .
black --check .
mypy
```

## Configuration

`.env.example` is a placeholder for later batches. Copy it to `.env` and set
`CI_AGENT_ENV` to one of `local` (default), `dev`, or `prod`. Never commit
real secrets.
