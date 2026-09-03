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

**Current status (Batches 1–3 implemented):**

- **Batch 1** — canonical data models (`PipelineSpec`, `PolicySpec`,
  `ExecutionPlan`, `EvidenceModel`, Report Section 4.1) and the versioned
  governance catalog (Section 6 policy families, Section 14 intake
  questionnaire).
- **Batch 2** — Audit Store (hash-chained, append-only; Sections 4.2/9), the
  Ingress / Trigger Gateway (`POST /webhooks/github` with signature
  verification, replay protection, repository/branch allowlists, run-ID
  issuance), and the Requirements Resolver (intake answers → validated
  `ProjectProfile`).
- **Batch 3** — Policy Decision Point (OPA-backed, fail-closed, Section 6
  policy-as-code) and the template-driven Planner (Phase A stage templates →
  validated `ExecutionPlan`).

Not yet implemented (later batches): runner adapters (GitHub Actions YAML
generation), policy-decision enforcement inside a running orchestration, the
Evidence Store persistence layer, Report Generator, and any AI integration.

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
│   └── schemas/        #   JSON Schemas validating the YAML/templates at load time
├── db/                 # SQLAlchemy Base/engine + ORM models + Alembic migrations
├── audit/              # AuditStore: runs, hash-chained audit trail, delivery dedupe
├── ingress/            # FastAPI Trigger Gateway (webhooks/github, /healthz)
├── resolver/           # Intake answers -> validated ProjectProfile
├── policy/             # Policy Decision Point + thin OPA REST client
└── planner/            # Approved stage templates -> ExecutionPlan
governance/rego/        # Rego policy files (loaded by OPA; reviewed like code)
alembic.ini             # Alembic configuration (audit database migrations)
docker-compose.yml      # Local OPA service (Batch 3)
scripts/
└── validate_governance.py   # CLI: validates all governance files, non-zero exit on failure
tests/                  # pytest unit + integration tests
```

## Setup

Requires Python 3.11+.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # optional; sensible local defaults apply
```

## Configuration (environment variables)

| Variable | Default | Notes |
| --- | --- | --- |
| `CI_AGENT_ENV` | `local` | `local` / `dev` / `prod` |
| `DATABASE_URL` | `sqlite:///./ci_agent.db` | SQLAlchemy URL; use Postgres in deployment |
| `GITHUB_WEBHOOK_SECRET` | dev default in `local` only | **Required in dev/prod — startup fails loudly without it** |
| `OPA_URL` | `http://localhost:8181` | OPA REST endpoint (Batch 3) |
| `OPA_TIMEOUT_SECONDS` | `5` | Policy evaluation timeout (Section 10) |

## Run the tests

```bash
pytest -v                        # everything; integration tests skip if OPA isn't running
pytest -m integration -v         # integration tests only
```

The OPA integration tests run for real when OPA is up (see next section) and
skip with a clear message otherwise.

## Validate the governance catalog

```bash
python scripts/validate_governance.py
```

Prints a PASS/FAIL line for each of the 10 governance files (3 catalog files +
7 policy families) and exits non-zero if any file fails schema validation.

## Database migrations

```bash
alembic upgrade head        # creates run_records, audit_log_entries, processed_deliveries
```

`DATABASE_URL` overrides the target database. In `local` envs the app also
auto-creates tables at startup for convenience; real deployments should rely
on Alembic only.

## Run the ingress locally

```bash
uvicorn ci_agent.ingress.app:app --host 0.0.0.0 --port 8000
curl http://localhost:8000/healthz
```

Local dev uses the documented dev webhook secret
(`ci-agent-local-dev-webhook-secret`), so a signed request can be produced with:

```bash
BODY='{"ref":"refs/heads/main","after":"abc123","repository":{"full_name":"example-org/payments-api"}}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "ci-agent-local-dev-webhook-secret" -hex | sed 's/.* //')"
curl -s -X POST http://localhost:8000/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -H "X-GitHub-Delivery: demo-001" \
  -H "X-Hub-Signature-256: $SIG" \
  -d "$BODY"
# -> {"run_id":"...","status":"accepted"}
```

The endpoint's job ends at "run accepted, evidence recorded": rejections are
audited, and every accepted run gets a hash-chained audit trail.

## Run OPA + the Policy Decision Point

```bash
docker-compose up opa
# or without Docker:
opa run --server --set=decision_logs.console=true governance/rego
```

OPA serves the Rego policies at `http://localhost:8181` (`GET /health` to
check). Any OPA >= 0.64 works (the policies use `import rego.v1`, which is
also forward-compatible with OPA 1.x). With OPA running, the integration
tests exercise the real policy engine:

```bash
pytest -m integration -v
```

## Lint, format, type-check

```bash
ruff check .
black --check .
mypy
```

## Configuration

`.env.example` documents every environment variable. Never commit real
secrets — the webhook secret is read only from the environment via
`ci_agent.config.settings`.
