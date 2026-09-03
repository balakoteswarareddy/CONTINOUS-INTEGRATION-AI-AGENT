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
├── planner/            # Approved stage templates -> ExecutionPlan
├── adapters/           # RunnerAdapter seam + GitHub Actions compiler/client
├── observer/           # Execution Observer: stage records, webhook mapping,
│   │                   #   reconciliation CLI (Section 10)
│   └── ...
├── orchestrator/       # Phase A RunState machine + orchestrator + approvals
├── projects/           # Project registry + admin onboarding API
├── reporting/          # Evidence assembler + developer/mgmt/compliance views
└── reliability/        # Retries, circuit breakers, concurrency guard
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
| `ADMIN_API_KEY` | dev default in `local` only | **Required in dev/prod — admin API auth (Batch 5)** |
| `MAX_CONCURRENT_RUNS_PER_PROJECT` | `3` | In-flight dispatch quota per project |

## Identity policy: deny-by-default + local-dev override

The committed
[`governance` identity policy](src/ci_agent/governance/catalog/policies/identity_policy.yaml)
ships with **EMPTY** `allowed_repositories` / `allowed_branches` — a true
deny-by-default posture (Section 7): in `dev`/`prod`, every webhook for an
unconfigured repository is rejected with an audited 403, and `plan_approval`
fails closed. **You must explicitly configure these allowlists for your
environment before onboarding real repositories.**

A working example allowlist (`example-org/*`, `main`, `release/*`,
`feature/*`) lives in
`src/ci_agent/governance/catalog/policies/examples/identity_policy.local-dev.yaml`.
It is loaded ONLY when `CI_AGENT_ENV=local` (with a loud startup warning,
"⚠ Using LOCAL-DEV identity policy override — do not use in shared/prod
environments"). Never copy it into a shared/deployed environment as-is.
`scripts/validate_governance.py` FAILS if the committed policy ever becomes
permissive again, and validates the example file against the policy schema.

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
alembic upgrade head        # 0001 runs/audit/deliveries, 0002 stage executions +
                            # dispatch tracking, 0003 run state + approvals +
                            # policy decisions + project registry
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


## Batch 4/5: live dispatch + full Phase A orchestration (MVP complete)

The control plane now covers the whole Section 5.1 Phase A loop:

```
webhook -> run -> plan_approval (OPA) -> dispatch (GitHub Actions) ->
observer stage transitions -> policy_gate (OPA) -> [approval] ->
merge decision Check Run -> evidence + reports
```

### 1. Configure credentials (live dispatch)

```bash
export GITHUB_PAT=github_pat_...        # or the GitHub App triple:
# export GITHUB_APP_ID=12345
# export GITHUB_APP_PRIVATE_KEY_PATH=/secure/path/app.pem
# export GITHUB_INSTALLATION_ID=67890
export ADMIN_API_KEY=$(openssl rand -hex 24)   # required outside `local`
```

### 2. Onboard a project (admin API)

```bash
curl -X POST http://localhost:8000/admin/projects \
  -H "X-Admin-Key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"repository": "example-org/payments-api", "intake_answers": { ...intake schema answers... }}'

curl -X POST http://localhost:8000/admin/projects/example-org%2Fpayments-api/pipeline-spec \
  -H "X-Admin-Key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"spec": { ...PipelineSpec JSON... }}'
```

### 3. Trigger + watch a run

Send a signed webhook (see above). The response acknowledges acceptance and
kicks off orchestration: the run lands on branch `ci-agent/<run_id>` in your
repo with one job per stage and a `ci-agent-results` artifact. Observer
webhooks (`workflow_run`, `check_run`) advance the run state; when the tool
stages finish, the policy gate evaluates and the merge decision is published
as a Check Run linking the compliance report.

```bash
curl "http://localhost:8000/runs/<run_id>"                        # run summary
curl "http://localhost:8000/runs/<run_id>/report?view=developer"  # per-stage + hints
curl "http://localhost:8000/runs/<run_id>/report?view=management" # outcome + lead time
curl "http://localhost:8000/runs/<run_id>/report?view=compliance" # full evidence
```

High-risk projects pause at `awaiting_approval`:

```bash
curl -X POST "http://localhost:8000/runs/<run_id>/approve" \
  -H "Content-Type: application/json" -d '{"approver": "alice"}'
```

Reconciliation fallback (Section 10, missed webhooks):

```bash
python -m ci_agent.observer.reconciliation --run-id <run_id>
```

Live-dispatch integration test (needs real credentials):

```bash
export CI_AGENT_TEST_REPO=example-org/payments-api
pytest tests/integration/test_github_actions_dispatch.py -v
```
