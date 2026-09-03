# Batch 1 Notes — Decisions, Deltas & Deviations

Required by Batch 1 Section 5 ("flag it in a NOTES.md file instead of building
it early") and Section 6 (document any deviations/suppressions).

## 1. Reference document not present in the workspace

`CI-Agent-Production-Architecture-Report.pdf` was **not present** in the
repository or workspace when Batch 1 was executed, so it could not be copied
to `docs/architecture-reference.pdf` (a placeholder `docs/README.md` explains
this instead). All content was implemented strictly from the Batch 1
instructions themselves, which quote the governing requirements (Sections 1,
2, 4.1, 6, 7, 13, 14). No architecture was invented beyond them. **Action:**
drop the PDF into `docs/architecture-reference.pdf` and re-check the section
cross-references.

## 2. Documented deltas from the Batch 1 Section 3 file layout

| Delta | Reason |
| --- | --- |
| `docs/architecture-reference.pdf` absent, `docs/README.md` added instead | PDF not supplied to the workspace (see §1). |
| `governance/schemas/provider_matrix.schema.json` added | Required by DoD item 3 (the CLI must validate the provider matrix) and by Task C's loader contract ("All must validate against the corresponding JSON Schema"). Section 3's schema listing omitted it. |
| `tests/unit/test_config/test_settings.py` added | Task A introduces `settings.py`; it needed the coverage its acceptance check implies. |
| `NOTES.md` added | Required by Section 5 for flagging. |

No other structural deltas. Every file/path in Section 3 exists exactly as
listed (with the `ci-agent/` root mapped onto this repository's root).

## 3. Validator additions (correctness checks, not new fields)

The spec explicitly requires the `PipelineSpec` dependency check and asks that
"(c) at least one custom validator … is exercised both for pass and fail" per
model, so each model carries at least one real validator:

- `PipelineSpec`: stages non-empty; `depends_on` must reference existing stage
  ids (spec-mandated); duplicate stage ids rejected (integrity of the DAG);
  dependency cycles (including self-dependencies) rejected via Kahn's
  algorithm — a cyclic stage graph can never execute.
- `PipelineSpec.policy_version` / `PolicySpec.policy_version`: must be valid
  semantic versions — the spec describes the field as a "semantic version
  string" cross-linking the two models, so malformed versions fail at
  construction.
- `ExecutionPlan`: duplicate `step_id`s rejected (evidence references steps by
  id, so ids must be unambiguous).
- `EvidenceModel`: if both `timestamps["started_at"]` and
  `timestamps["completed_at"]` are present, completion must not precede start.
- Numeric sanity: `ResolvedStep.timeout_seconds > 0`,
  `RetryPolicy.max_retries >= 0`, `BuildPolicy.max_timeout_seconds > 0`.

## 4. Modeling decisions worth knowing

- **Frozen + closed models.** All canonical models use `frozen=True` and
  `extra="forbid"`: specs, policies, plans and evidence are immutable value
  objects, and unknown fields are rejected rather than silently dropped (a
  fail-closed posture, per Section 7 trust boundaries).
- **Empty allowlists are intentional.** The shipped governance defaults are
  deny-by-default (Section 7): `allowed_repositories`, `approved_images`,
  `allowed_base_images`, `registry_allowlist`, `allowed_model_providers`, etc.
  are empty — nothing is permitted until an operator explicitly allowlists it.
  This is deliberate posture, not an omission.
- **`approval_policy.approver_groups` ships empty** while approvals are
  required for `high`/`regulated` risk tiers. The future Policy Decision Point
  (Batch 3) must treat "approval required but no approver groups configured"
  as **fail-closed**.
- **`PolicySpec` boolean flags have no defaults** (e.g. `require_secret_scan`,
  `require_sbom`, `require_human_override`): constructing an unsafe policy by
  omission is impossible — authors must state each flag explicitly.
  Allowlist-style lists default to empty (deny-by-default), which is safe.
- **`StageDefinition.depends_on` / `required_tools` and similar list fields
  default to empty lists** — the spec says fields must be "explicitly required
  or defaulted"; these are safely defaultable.
- **`EvidenceModel.Finding.disposition`** is a free-form `str` per the Batch 1
  field list; consider an enum (`open | fixed | waived | …`) in a later batch
  once the waiver workflow (Section 6 exception management) is designed.
- **`ExecutionPlan.resolved_steps` may be empty** — unlike `PipelineSpec.stages`
  (where the spec explicitly mandates non-empty), plans may legitimately be
  generated incrementally by the Planner in a later batch. No emptiness check
  was imposed; only step-id uniqueness is enforced.
- **`settings.py` is a plain frozen dataclass**, not `pydantic-settings` — the
  spec allows "a minimal Pydantic BaseSettings-style class (or plain class)",
  and this avoids an extra runtime dependency in a batch that is types-only.

## 5. Lint suppressions

- ruff per-file ignore `F401` in `__init__.py` files (public re-exports).
- ruff per-file ignore `E402` in `scripts/validate_governance.py` (sys.path
  bootstrap must precede the `ci_agent` import so the CLI runs from a plain
  checkout without installation).
- ruff per-file ignore `UP042` in `core/models/common.py`: UP042 wants
  `enum.StrEnum`, but the Batch 1 spec explicitly mandates that all enums
  "subclass `str`, `Enum`", so the exact prescribed form is kept.
- No other rules are suppressed. `ruff check .` passes clean with the rule
  set configured in `pyproject.toml` (`E,W,F,I,B,UP,SIM,C4,RUF`).

## 6. Out of scope (flagged, not built — per Batch 1 Section 5)

Components the full architecture requires but later batches own: Policy
Decision Point / policy engine evaluation, Planner (PipelineSpec →
ExecutionPlan compiler), runner adapters (GitHub Actions), Evidence Store
persistence, Report Generator, AI integration, intake answer storage,
secrets/identity binding, and the waiver/exception workflow. None of these are
stubbed in code; the models above define the contracts they will implement.

---

# Batch 2 Notes — Audit Store, Ingress, Requirements Resolver

## Deviations & decisions (per Batch 2 Section 6/8 traceability rules)

1. **`AuditLogEntry.run_id` is an indexed plain column, not a SQL FK.** The
   batch spec asks for both (a) an FK to `run_records.run_id` and (b) audit
   entries for rejections that happen BEFORE any run exists (invalid
   signature, disallowed repository/branch, duplicates). Both cannot hold:
   a pre-run rejection has no parent row. Resolution: the FK constraint is
   relaxed to an indexed column, and pre-run rejections chain under a
   synthetic id `rejected:<delivery_id>` (or `rejected:unknown` when the
   delivery header is absent). Requirement (b) — "even rejections are
   auditable events" — wins because Sections 4.2/9 demand complete audit
   trails; the alternative (creating RunRecords for rejected requests) would
   pollute run history with non-runs.
2. **`project_id` at ingress time = repository full name.** The project
   registry / onboarding API does not exist yet (explicitly out of scope per
   Task C's note), so the webhook writes the repository full name as a
   placeholder project identifier. The resolver produces richer profiles but
   persisting `ProjectProfile` is deferred (per Task C: no DB wiring yet).
3. **Naive-UTC datetime convention in the DB layer.** SQLite cannot round-trip
   timezone offsets, and the audit hash chain requires byte-stable
   `created_at.isoformat()` values. All DB-layer datetimes are therefore
   naive-UTC by convention; the application layer treats them as UTC.
   Documented in `db/models.py`.
4. **`identity_policy.yaml` now ships a scoped example allowlist**
   (`example-org/*`, branches `main`/`release/*`/`feature/*`) replacing Batch
   1's empty defaults, so the ingress is functional out of the box. This
   supersedes the Batch 1 NOTES bullet ("empty allowlists are intentional") —
   deny-by-default is preserved for anything not matching the globs.
   Operators must scope this file before real deployment.
5. **`RequirementsResolver.resolve()` gained an optional `policy_version`
   keyword.** The spec's `ProjectProfile.policy_version_pinned` needs a
   source; when omitted it defaults to `load_org_policy_version()` (a new
   governance loader helper verifying all 7 policy files agree on one
   version). Purity kept: file reads only, no DB/HTTP.
6. **Intake answer shape**: answers may be flat (`{question_id: value}`) or
   nested by section id; both are normalized. An empty list is a VALID answer
   for `string_list` questions (an empty allowlist is deny-by-default, not an
   omission) but counts as "unanswered" for scalar questions.
7. **Webhook error mapping**: unsupported event → 400 `unsupported_event`;
   malformed JSON / missing delivery header / undeterminable branch or SHA →
   400 `payload_invalid` (justified by Section 4.2 "Validate ... source
   revision" + rejections-are-auditable). Duplicate delivery → HTTP 200
   idempotent with `duplicate_rejected` audit (spec/Section 10). Branch
   allow-list applies to both supported events (head ref for PRs, `ref` for
   push).
8. **Local env auto-creates tables.** In `CI_AGENT_ENV=local` the app runs
   `Base.metadata.create_all` at startup for dev ergonomics; real deployments
   use `alembic upgrade head` (see README). Alembic is exercised by a
   dedicated migration test plus manual run.
9. **Extra test directory** `tests/unit/test_db/` for the Alembic migration
   test (the spec requires a dedicated migration test; this keeps db tests
   grouped).
10. **Dev webhook secret constant** `LOCAL_DEV_WEBHOOK_SECRET` is the
    documented local-only fallback (also in `.env.example`); dev/prod fail
    startup loudly without `GITHUB_WEBHOOK_SECRET` (tested).
11. **`RUN_STATUS_ACCEPTED`** is the initial run status ("free string
    constrained at app layer" per the spec; the state machine arrives later).

## Verification evidence (manual DoD flow, run against uvicorn on :8000)

```
healthz:          200 {"status": "ok"}
signed webhook:   202 {"run_id": "3d28e409-...", "status": "accepted"}
replay:           200 {"detail": "duplicate delivery, ignored"}
tampered sig:     401 {"detail": "invalid signature"}
RunRecord:        3d28e409-... example-org/payments-api push cafe5678abcd accepted
audit trail:      [('webhook_received', 'GENESIS'), ('run_created', 'c813f4e9f9f0')]
verify_chain:     True
delivery marked:  True
```

---

# Batch 3 Notes — Policy Decision Point & Planner

## Deviations & decisions (per Batch 3 Section 6/7 traceability rules)

1. **`Planner.build_execution_plan` gained a required `run_id` keyword.** The
   batch text says "Assign a run_id (passed in, comes from the ingress-created
   run)" but the given signature had no run_id parameter; the keyword resolves
   that contradiction.
2. **`PolicyInputFacts` extends the spec'd five fields** with optional
   `approvals`, `ai_invocation` and `run_id`: the PDP must evaluate approval
   gates (which inherently need approval records as runtime facts) and must
   persist every evaluation via `AuditStore.append_event(run_id, ...)`
   (Task A requirement). Without these fields neither is possible.
3. **Unknown `stage_id` in `evaluate_gate` evaluates ALL seven families**
   (fail-closed breadth) and prepends a note reason, instead of erroring or
   passing.
4. **`internal.*` gate steps are exempt from tool approval** in both the
   Planner cross-check and tool_policy.rego: Report Section 5.1 defines them
   as control-flow stages, not tool executions ("represent them as
   ResolvedStep entries with tool_name=internal.*").
5. **PipelineSpec owns WHAT runs; the template owns HOW.** A pipeline stage
   with no template entry raises `TemplateMismatchError` (hard fail, per the
   guardrail against silent workarounds); template stages the spec doesn't
   use are simply not planned. `TemplateMismatchError` is an additional
   exception type beyond the spec'd `UnapprovedToolError` (flagged here).
6. **Identity facts are checked only when provided** (identity binding
   arrives with runner adapters); repository/branch checks are always
   enforced by identity_policy.rego. Egress-domain runtime facts default to
   empty until runners enforce networking; `step_timeout_seconds` (max across
   plan steps) IS enforced against `max_timeout_seconds`.
7. **Catalog updates** (governance config, not code): `tool_policy.yaml` now
   approves exactly the pinned tools/images used by the Batch 3 templates,
   and `build_policy.yaml` allowlists their base images + required package
   registries. `identity_policy.yaml` keeps the Batch 2 example-org allowlist.
   `policy_version` stays "1.0.0" (pre-release governed baseline; content
   changes are tracked in these notes). Deny-by-default still holds for
   anything unlisted.
8. **OPA pinned to `openpolicyagent/opa:0.67.1-static`** in docker-compose;
   Rego uses `import rego.v1` (works on OPA >= 0.64 and OPA 1.x). Live
   verification in the development sandbox used a real OPA 0.70.0 binary
   serving `governance/rego`.
9. **Per-project policy overrides deferred** (spec: MVP uses the org-wide
   governed catalog only). `PolicyDecisionPoint` accepts an optional
   `PolicySpec` for that future capability and otherwise loads the catalog
   via the new `governance.loader.load_policy_spec()`.
10. **`respx` added as a dev dependency** (spec-preferred httpx mocking).
11. **Runtime-fact derivation is explicit and documented** in
    `policy_decision_point._build_runtime_facts`: repository/branch from the
    pipeline spec; tools/images from the proposed plan;
    `scans_executed` maps planner scan stages (secret_scan/dependency_scan/
    sast) onto the security Rego's scan vocabulary.

## Verification evidence (real OPA 0.70.0 serving governance/rego)

```
integration tests: 8 passed, 0 skipped (with OPA live)
manual evaluate_gate against live OPA:
  policy_gate (clean plan)          -> pass  | reasons: []
  policy_gate (critical finding)    -> fail  | security_policy: severity "critical": 1 findings exceed threshold 0
  human_approval (no approver groups) -> fail | approval_policy: ... (fail closed)
  audit trail: 3x policy_decision entries; verify_chain == True
```

## Batch 3 sample ExecutionPlan (DoD 4, abridged)

```
run_id: run-dod4-1, pipeline_spec_ref: sha256:3cd34b57...
checkout.git -> format_lint.ruff -> sast.bandit -> unit_tests.pytest
  -> secret_scan.gitleaks -> dependency_scan.pip-audit
  -> policy_gate.internal.policy_gate -> human_approval.internal.human_approval
  -> merge_decision.internal.merge_decision
```

---

# Batch 4 Notes — Runner Adapter (GitHub Actions) & Execution Observer

## Deviations & decisions

1. **Jobs-per-stage workflow compilation.** The batch offered "one job per
   stage" or "steps within a single job" and leaned single-job for MVP, but
   Task B requires mapping `check_run` webhook events to individual stage
   transitions — GitHub emits one Check Run per JOB. We therefore compile one
   job per stage (id `stage-<stage_id>`, name `<stage_id>` so
   `check_run.name == stage_id`), wired via `needs:` from
   `ResolvedStep.depends_on`. Documented here as the deliberate choice.
2. **`ResolvedStep.depends_on` added** (Batch 1 model, defaulted, backwards
   compatible): adapters need the dependency graph to build `needs:`; the
   Planner now populates it from PipelineSpec stages.
3. **`RunnerAdapter.compile` accepts optional generic `metadata`** (target
   repository, source revision): an ExecutionPlan deliberately carries no
   dispatch coordinates, but dispatch needs them. Keys are generic strings —
   no vendor types in the seam.
4. **Command template ids** follow our Batch 3 templates (`lint.ruff`,
   `tests.pytest`, `scan.pip-audit`, `scan.npm-audit`, ...). The batch's
   example list used different ids (`unit_tests.pytest`,
   `dependency_scan.pip_audit`); our canonical ids are the ones the Batch 3
   templates actually reference, and a test enforces every template id is
   allow-listed. `checkout.default: null` = native pinned `actions/checkout@v4`.
   Gate stages (`internal.*`) never consult the registry (control-plane
   orchestrated placeholder jobs).
5. **workflow_dispatch chosen over push triggers** for explicit control and
   idempotent re-dispatch; the compiled workflow's `on:` is
   `workflow_dispatch` only, `permissions: contents: read` (least privilege —
   the merge decision is posted via the adapter's own credential, not the
   runner's token).
6. **Run-id resolution** after `workflow_dispatch` uses a bounded retry
   (5 attempts, linear backoff) against `GET /actions/runs?branch=`; returns
   `None` (recorded) if unresolved rather than failing the dispatch.
7. **check_run → run correlation**: GitHub's check_run payload has no branch,
   so runs are matched by `RunRecord.source_sha == check_run.head_sha`
   (most recent dispatched run). Limitation: two simultaneous dispatches from
   the same sha could correlate ambiguously; branch-based correlation is used
   for workflow_run events, which carry `head_branch`. Documented as an MVP
   simplification.
8. **Observer pseudo-stage `workflow`**: workflow_run events record overall
   run status under stage_id `workflow` (plus updating nothing else). Unmatched
   observer events are audited under synthetic run id `observer:unmatched`.
9. **First-write-wins transitions**: the monotonic transition table is
   enforced on UPDATES; a record's first write may land directly on a terminal
   status (reconciliation observes terminal states without intermediates).
   Same-status re-record is an idempotent no-op; rejections are audited
   (`stage_transition_rejected`) and raise `InvalidStageTransitionError`.
10. **Reconciliation** prefers the structured `ci-agent-results` artifact
    (zip -> JSON parsed), falls back to check-run statuses, then to the
    overall workflow status on the `workflow` pseudo-stage. Racing webhook
    conflicts are counted, not raised. CLI: `python -m
    ci_agent.observer.reconciliation --run-id <id>`; scheduler wiring is a
    deployment concern.
11. **Credentials**: PAT passthrough (MVP fallback) or GitHub App JWT ->
    installation-token exchange (pyjwt + cryptography, token cached with a
    safety margin). Only a redacted indicator is ever logged. Full
    OIDC/workload-identity hardening of this credential (Section 7.2) is
    deferred to pre-production hardening.
12. **Observer endpoint response**: observer events return an explicit 200
    (the route's declared 202 is for run creation); duplicate observer
    deliveries stay idempotent 200 with `duplicate_rejected` audit.
13. Integration test `test_github_actions_dispatch.py` requires real
    credentials + `CI_AGENT_TEST_REPO` and otherwise skips; it was NOT run
    here (no live credentials in this environment) — see README for the
    exact manual procedure.

## Manual dispatch test status

Not executed: no GitHub credentials are available in this sandbox. The test
is wired to run for real when `GITHUB_PAT` (or App vars) and
`CI_AGENT_TEST_REPO` are exported; all logic paths around it are covered by
respx-mocked client tests and adapter unit tests.

---

# Batch 5 Notes — Orchestrator, Reporting, Reliability (MVP completion)

## Design decisions & deviations

1. **State adjacency.** `sast` and `unit_tests` are parallel jobs, so
   `SAST_DONE <-> TESTS_DONE` transitions are allowed in either order;
   `SECURITY_CHECKED` fires only when BOTH scans are terminal-passed, making
   the policy gate order-safe under out-of-order webhooks. `format_lint`
   chains `BASELINE_VALIDATED -> LINTED` (both transitions dual-written).
2. **Gate timing.** The policy gate runs when all six tool stages are passed
   (checked from StageExecutionRecords, not from event arrival order). Events
   arriving after a terminal state are graceful audited no-ops (Section 10).
3. **`CallerError` vs `OrchestrationError`.** Malformed/not-actionable API
   requests (approve on a non-AWAITING_APPROVAL run -> HTTP 409) never mutate
   run state; internal orchestration failures park the run in `ERROR`
   (fail closed) via the same dual-write as normal transitions.
4. **Approval rule (MVP).** `risk_tier == high` requires human approval;
   everything else auto-approves after a passing policy gate. `PipelineSpec.
   approvals_required` is not yet consulted (flagged below).
5. **Merge decision Check Run** is named `ci-agent merge decision`; the
   observer skips it (and `ci-agent-results`) so control-plane check runs are
   never mistaken for stages. Its summary links
   `/runs/{id}/report?view=compliance`.
6. **PDP persistence.** Every PDP decision (including OPA-unavailable
   fail-closed ones) is written to `policy_decision_records` (migration 0003)
   in addition to the audit event; the compliance report reads these rows.
7. **Registry keys.** `project_profiles.project_id` IS the repository full
   name ("org/repo") — the same value the ingress writes to
   `run_records.project_id`. The resolver-derived internal project id is kept
   verbatim inside the profile JSON for traceability. Admin pipeline-spec
   routes use `{project_id:path}` because project ids contain slashes.
8. **Evidence honesty.** `tool_versions`, `artifacts`, `attestations` stay
   EMPTY until later batches populate them (never fabricated, never omitted).
   Failed stages produce one exit-code-only HIGH finding each (MVP; Batch 6
   replaces with real scanner parsing).
9. **Retries.** `retry_transient_external_call` (tenacity: 3 attempts,
   exponential 0.5s cap 5s, transport + 5xx only) decorates exactly
   `OPAClient.evaluate` and `GitHubClient.request`. The PDP's
   `evaluate_gate` has no retry (verified by an inspection test): a policy
   deny is a decision, not a failure.
10. **Circuit breaker: hand-rolled** (~80 lines, threading.Lock, closed/
    open/half-open) instead of pybreaker — fewer dependencies, explicit and
    fully tested. The breaker-wrapped OPA path surfaces
    `BreakerOpenError` -> `OPAUnavailableError`, so the PDP's fail-closed
    behaviour is preserved even with an open breaker (tested).
11. **Concurrency guard is in-process** (thread-safe counters). Multi-replica
    deployments need a shared lease store — deferred below.
12. **E2E audit trail growth.** With orchestration wired into the webhook
    (entry point 1), the Batch 2 e2e assertion was relaxed from "trail equals
    [webhook_received, run_created]" to "trail STARTS with those events" —
    later entries belong to the orchestrator (documented evolution).
13. **Backup/recovery.** `src/ci_agent/reliability/backup_notes.md` is an
    HONEST ops document: no backup automation exists in the MVP; it lists the
    pre-production plan (encrypted DB backups, audit-segment export, RPO/RTO,
    secret rotation runbook).

## Consolidated deferred-items list (all batches)

> **PRE-PRODUCTION GATE (blocks real rollout, does not block further
> development):** Live GitHub E2E dispatch test has never been executed
> against a real repository — sandbox credentials are a GitHub App
> installation token scoped with all repo permissions denied (verified via
> direct API probing: 403 on /user, check-runs, dispatches). Must be
> executed with a PAT (repo+workflow scopes) or a properly-scoped GitHub App
> against a disposable repository, with evidence (pass scenario + fail
> scenario) attached to NOTES.md, BEFORE onboarding any real repository or
> presenting this system as production-ready. Test harness is fully wired
> and waiting (test_github_actions_dispatch.py) — this is a
> credentials/access gap only, not a code gap.

1. Reference architecture PDF is not in the repo; docs/README.md stands in
   (Batch 1). All section numbers cite the report from the batch specs.
2. AI/LLM stages: permanently out of scope for this MVP (100% deterministic).
3. Scanner findings parsing, SARIF ingestion, per-finding dispositions/waivers
   -> Batch 6 (exit-code-only findings until then).
4. SBOM generation, artifact signing/attestation, artifact publishing ->
   Batch 7 (`EvidenceModel.artifacts/attestations` stay empty until then).
5. Phase B (build/container/publish stages) -> later batch; Phase A only here.
6. Runner credential hardening: OIDC/workload identity for the GitHub App
   token exchange is pre-production; PAT is the documented MVP fallback.
7. Admin API authn: static `X-Admin-Key` (MVP); SSO/RBAC/mTLS -> hardening.
   Approver identity is a plain string (no SSO binding).
8. Concurrency guard: single-process only; Redis/DB lease store for replicas.
9. Reconciliation scheduler: CLI exists; cron/systemd/worker wiring is a
   deployment concern.
10. check_run -> run correlation is sha-based (head_sha == source_sha);
    two simultaneous dispatches of the SAME sha are ambiguous (workflow_run
    branch correlation disambiguates those events). Documented MVP limit.
11. `PipelineSpec.approvals_required` not yet consulted by the approval rule
    (risk-tier rule only) — revisit with Batch 6 policy enrichment.
12. Live GitHub dispatch integration test requires real credentials; it was
    NOT executed in this environment (no creds) — see README for the manual
    procedure. All other paths are covered by mocked tests + real-OPA
    integration tests.
13. Backup/DR automation: none (see reliability/backup_notes.md).
14. Breakers are wired/available on app.state but the HTTP-facing adapters do
    not yet route every call through them (retries are active on both
    external clients); completing breaker wrapping of every GitHubClient
    method is a small hardening follow-up.

---

# Batch 5.1 Notes — MVP Hardening Close-out (Pre-Sign-off Fixes)

## ITEM 1 — Real GitHub end-to-end test: **BLOCKED (credentials), with probe evidence**

The batch forbids fabricating this item, so here is the precise blocker.

**What was probed (2026-09-03, `gh` CLI + GitHub REST from this sandbox):**
- Sandbox auth exists: `gh auth status` reports a `GH_TOKEN` for
  `arena-ai-coding-agent[bot]` — but it is a GitHub **App installation token**,
  not a user PAT.
- `GET /user` → 403; `GET /user/repos` → 403 (cannot even list repos).
- `GET /repos/balakoteswarareddy/CONTINOUS-INTEGRATION-AI-AGENT` → the
  installation sees exactly ONE repo, with
  `permissions: {admin:false, maintain:false, push:false, pull:false,
  triage:false}` (contents read via git push happens through a separate
  pre-configured git credential path; the REST API grants nothing writable).
- `POST /repos/.../check-runs` (Checks:write probe) → **403** "Resource not
  accessible by integration".
- `POST /repos/.../actions/workflows/x/dispatches` (Actions:write probe) →
  **403**.
- `gh repo create ci-agent-e2e-probe` (repo creation probe) → **403**
  (GraphQL `createRepository` not accessible).

Conclusion: this token can **read** public API metadata of the one bound repo
but cannot create repositories, push workflow dispatches, or create check runs
— every capability the real E2E requires. Running the flow against a repo we
cannot write to is impossible, and mocking it would violate the batch rules.

**What is needed from you (either option):**
1. A fine-grained or classic **PAT** with at least: `repo` (or
   Contents+Pull-requests+Checks+Administrative read for a private repo) and
   **`workflow`** scope, plus permission to create one disposable private
   repository; then export per README Batch 4/5 sections:
   - `GITHUB_PAT=<token>`
   - `CI_AGENT_TEST_REPO=<owner>/<disposable-repo>`
   - (GitHub App vars remain optional — PAT is the documented MVP fallback.)
2. OR: create the disposable repository yourself and provide a PAT/APP
   credential pair scoped to it.

The moment credentials exist: the existing
`tests/integration/test_github_actions_dispatch.py` (pass + deliberately
failing-stage scenarios) runs unmodified, plus the manual flow documented in
README (signed webhook → dispatch → observer/reconciliation mid-flight →
policy gate → merge-decision Check Run → compliance report + `verify_chain`).
Everything up to the GitHub boundary is already exercised by real-OPA
integration tests; only the last mile needs the credential.

## ITEM 2 — Identity policy deny-by-default: **DONE**

1. Committed `src/ci_agent/governance/catalog/policies/identity_policy.yaml`
   reverted to EMPTY `allowed_repositories` / `allowed_branches` (true
   deny-by-default, Section 7). Batch 2's convenience allowlist is gone from
   the shipped default.
2. The example moved verbatim to
   `catalog/policies/examples/identity_policy.local-dev.yaml` with a loud
   header ("LOCAL DEVELOPMENT OVERRIDE — NEVER USE IN SHARED/PROD").
3. Loader gained `load_identity_policy(local_dev_override)` and
   `load_policy_spec(local_dev_override)` (only the identity family swaps).
   `create_app` loads the override ONLY for `CI_AGENT_ENV=local` and logs
   `⚠ Using LOCAL-DEV identity policy override ... do not use in shared/prod
   environments` at WARNING level; dev/prod always get the committed file.
4. Tests switched from implicit-permissive-production to explicit local-dev
   override (`live_pdp` fixture, Phase A flow fixture) or inline fixtures.
5. README documents the split ("committed default policy = deny everything;
   configure allowlists per environment before onboarding").
6. `scripts/validate_governance.py` now (a) validates the example file, and
   (b) FAILS if the committed identity policy ever ships non-empty
   allowlists again — a permanent regression guard.
7. New tests: committed default empty; override file separate & permissive;
   spec override swaps identity family only; local app loads override +
   warning logged; dev app no warning + empty lists; **dev-mode webhook for
   an allowlist-shaped repo is rejected 403** (deny-everything proof);
   local-mode accepts `example-org/*` but still rejects `rogue-org/*`.

## ITEM 3 — Combined approval rule: **DONE**

Rule (documented in `PhaseAOrchestrator._approval_triggers`):
`approval_required = (profile.risk_tier in
PolicySpec.approval_policy.require_human_approval_for) OR
(PipelineSpec.approvals_required)`. Both signals are first-class and
ADDITIVE — either alone is sufficient; neither can cancel the other.

- The Batch 5 hardcoded `== "high"` check is gone: `create_app` passes
  `frozenset(policy_spec.approval_policy.require_human_approval_for)` (the
  governed catalog currently lists `high, regulated`); the constructor
  default only mirrors that governed value for standalone tests.
- WHY-recording: the `AWAITING_APPROVAL` transition carries a human-readable
  reason (`human approval required by: risk_tier:high,
  pipeline_spec.approvals_required`) AND a structured `approval_required`
  audit event with `{"triggers": [...]}` — the compliance package includes
  both via the audit trail (Section 18 reconstructability). The advance
  result also returns `triggers`.
- Tests (all passing, `tests/unit/test_orchestrator/test_approval_rule.py`):
  the five documented cases — high+false (risk_tier trigger), low+true
  (pipeline_spec trigger), low+false (auto-approve, no approval event),
  high+true (both triggers, both in the transition reason) — plus
  policy-list-with-medium → medium risk now requires approval, and the
  corollary (medium NOT in list → auto-approve).

## ITEM 4 — `RunRecord.status` vs `current_state`: **DONE (option a — DEPRECATE)**

Investigation findings (before any change):
- `status` was written exactly ONCE per run — `AuditStore.create_run` set
  `RUN_STATUS_ACCEPTED` ("accepted") and the ORM column default repeated it.
  NO code path ever updated it afterwards (Batch 5's orchestrator writes only
  `current_state`).
- Read paths: `GET /runs/{run_id}` (`"status": run.status`) and `__repr__`.
  (The `record.status` in report_models is `StageExecutionRecord.status` — a
  different, unrelated column.)
- So no active drift existed, but the exposed field was meaningless after
  creation ("accepted" forever) — misleading rather than corrupt.

Choice: **(a) DEPRECATE** — smallest, safest change; no migration, no
generated-column complexity, existing rows/tests unaffected.
- `status` column retained for backward compatibility, marked DEPRECATED in
  models.py (doc + comment); the explicit `status=` write removed from
  `create_run` (the ORM insert default remains the single legacy write; no
  code path updates it afterwards — frozen at "accepted").
- New `run_status_from_state(current_state)` in db/models.py is the ONLY
  sanctioned status vocabulary for display: None→"accepted",
  in-flight states→"in_progress", awaiting_approval/approved/rejected
  pass through, merge_decision_published→"published", failed/error pass
  through, unknown value→"error" (fail-closed). `GET /runs/{run_id}` now
  derives `status` from it (response semantics documented in the docstring;
  `current_state` remains in the response).
- Tests (`test_run_status_alignment.py`): mapping total over all 14 states +
  None; unknown state → "error"; a run driven through
  created→in-flight→published asserts at EVERY step that the legacy column is
  frozen while the derived status tracks current_state (and actually moves);
  an API test mutates current_state and shows the response `status` follows
  it while the stored column stays "accepted" — no drift is possible because
  nothing reads or writes the legacy column anymore.

## Batch 5.1 gate results

- Full suite: **441 passed, 1 skipped** (live-credential dispatch test; OPA
  live) — all prior batches still green.
- `ruff check .` clean; `black --check` clean; `mypy` clean;
  `scripts/validate_governance.py` 11/11 + deny-by-default guard PASS.

---

# Batch 6 Notes — Security Evidence Service (SAST/SCA/Secrets finding parsing)

Resequencing acknowledged: container scanning + SBOM/signing moved to Batch 7
(they need a built artifact). This batch = the Phase-A-native portion of the
original Stage 14. No container scanning, no SBOM here.

## Severity mapping decisions (explicit, no silent defaults)

1. **bandit**: 1:1 (HIGH/MEDIUM/LOW). Unknown words raise
   `UnknownSeverityError` — a changed tool format must never silently become
   "clean" or a guessed severity.
2. **gitleaks**: the JSON report has NO native severity. EVERY finding maps
   to CRITICAL (Section 5.1 Stage 7: secrets are incidents, not lint). A
   hardwired constant, documented in `gitleaks_severity()`.
3. **pip-audit**: real output carries no severity. With an enriched
   `cvss_score` we band CVSS-style (>=9 critical, >=7 high, >=4 medium, else
   low); unknown -> MEDIUM (documented default: an unscorable published
   vulnerability is worth tracking, never ignorable).
4. **npm-audit**: 1:1 over npm's vocabulary (critical/high/moderate/low/info;
   moderate -> MEDIUM).
5. **semgrep** (registered; nodejs sast stage): ERROR/WARNING/INFO ->
   HIGH/MEDIUM/LOW (semgrep has no "critical").
6. **eslint** (registered; nodejs lint stage): 2=error->HIGH, 1=warning->LOW
   (lint qualities, not CVSS — documented).

## Fixture shapes (sources)

Real documented tool output shapes, captured as committed fixtures under
`tests/fixtures/security_tool_outputs/` (clean + with-findings per tool):
bandit `-f json` (`results[]` with issue_severity/test_id/filename/
line_number); gitleaks `--report-format json` (array of {RuleID, File,
StartLine, Secret, Match, ...}); pip-audit `-f json` (`dependencies[]` with
`vulns[]` {id, fix_versions, aliases, description}); npm-audit `--json`
(`vulnerabilities{}` keyed by package, `via[]` advisory objects vs. strings,
`range`, npm>=9 shape).

## Design decisions

1. **"Couldn't parse" != "clean"** (batch requirement): parsers return
   `ParseOutcome{findings, warnings}`; malformed/empty/shape-invalid output
   yields warnings and is CLEAN=false. Missing `results[]`/`dependencies[]`/
   `vulnerabilities{}` keys are also shape warnings, not empty scans.
2. **Audit events carry COUNTS only** (`findings_collected`: {count,
   by_severity, parser_warnings}) — never finding payloads (a leaked secret
   must not enter the audit trail; tested).
3. **`findings_ref` = per-stage summary blob** (`{"count": N, "by_severity":
   {...}, "parser_warnings": [...]}`); `FindingRecord` rows are the detail
   source of truth. No duplication of full rows (documented in the model).
4. **Parser-warning incidents are AUDIT-backed** (not only the stage
   summary): reconciliation can observe a stage terminal before its row
   exists, so `parser_warnings()` reads the durable `findings_collected`
   events — the fail-closed flag survives any event ordering.
5. **Artifact download failure / absent artifact** in the app-level collector
   is flagged as a parser-warning incident (empty output -> warning) instead
   of raising past the observer: the anomaly becomes evidence and the gate
   fails closed; the webhook stays resilient. `UnknownParserError` still
   raises loudly.
6. **Secret redaction is structural**: the gitleaks parser never reads
   `Secret`/`Match` into the output model; a belt-and-braces assert re-checks
   every emitted finding; the grep-style test sweeps FindingRecord rows,
   audit payloads, and stage summaries for the fixture secret (PASSES).

## Wiring

- Compiler: scan/lint stages now upload their raw JSON reports
  (`ci-agent-scan-<stage_id>` artifacts, `if: always()` so failing scans
  still upload); `scan.pip-audit`, `scan.npm-audit`, `lint.eslint` commands
  were extended to emit JSON report files.
- Observer: `scan_evidence_collector` hook (wired in create_app) runs BEFORE
  a scan stage is marked terminal — findings exist before any policy gate.
- `_gate_facts` (orchestrator): findings now come from FindingRecord rows;
  parser warnings become HIGH `parser_warning_unparseable_output` findings;
  a FAILED scan stage with nothing persisted becomes HIGH
  `scan_failed_without_parseable_findings`. Real severity counts flow into
  `security_policy.rego` thresholds (verified against live OPA).
- Reports: new `?view=security` (scanner, rule_id, severity, component,
  location, disposition per finding + summary + warnings); the compliance
  package and EvidenceModel now carry REAL findings.

## MVP placeholder — fully removed (confirmation)

The Batch 5 "one exit-code-only HIGH finding per failed stage" logic is GONE:
`phase_a_orchestrator._gate_facts` (rewritten), `evidence_assembler`
(now queries FindingRecord; `EXIT_CODE_FINDING_SEVERITY` constant deleted).
Grep for `stage_exit_code_nonzero` returns only this NOTES entry. The old
report test was rewritten to plant a REAL gitleaks finding and assert its
CRITICAL severity/rule id.

## Batch 6 gate results

- Full suite: **478 passed, 1 skipped** (live-credential dispatch; OPA live).
- ruff / black / mypy clean. Alembic 0004 up/down/up verified.
- DoD mocked pipeline: bandit HIGH finding -> gate FAILS vs live OPA
  ("severity high: 1 findings exceed threshold 0"); clean scan -> publishes;
  unparseable output -> fails closed; security view shows real finding data.

**Flagged for follow-up**: the nodejs `lint.eslint` command now emits
`eslint-report.json` and the parser is registered, but the eslint upload is
wired to the `format_lint` stage generically — if a future nodejs template
splits lint/sast stages, revisit `REPORT_UPLOAD_STAGES` mapping (cosmetic).

---

# Batch 7 Notes — Phase B Supply Chain (build → SBOM → scan → sign → publish)

Completes Section 13 "Phase 2 — Security Supply Chain": the Section 5.2
nine-stage flow (full_build, integration_tests, coverage_gate, container_build,
sbom_generate, image_scan, sign_attest, publish, record_evidence) plus the
Section 6/18 exception/waiver workflow.

## Decisions requiring documentation

1. **SBOM format: BOTH SPDX and CycloneDX supported** (Section 8 "an approved
   format such as SPDX or CycloneDX" + Section 12 vendor neutrality — a SBOM
   adapter, not a format mandate). `SBOMService.parse_syft_output` detects the
   document family (`spdxVersion` vs `bomFormat`) and records `format` +
   `component_count`. The GOVERNED default (`artifact_policy.yaml
   sbom_format: spdx`) drives the compiled syft template
   (`-o spdx-json=sbom.json`), and a NEW artifact_policy.rego rule fails an
   artifact whose SBOM exists but is in the WRONG format (fires only when
   has_sbom is true; the missing-SBOM rule already covers absence).
2. **Signing: keyless preferred, test-key fallback in dev/test.** Section 7.2
   prefers KMS/HSM or keyless (OIDC) signing; keyless requires a cluster OIDC
   bridge this environment does not have, so the compiled sign command uses a
   runner-environment key (`cosign sign --key env://COSIGN_KEY ...`).
   **HARDENING ITEM (flagged):** switch to keyless OIDC (or KMS) before
   production; `--insecure-ignore-tlog` in the verify wrapper is likewise a
   dev/test posture. The agent NEVER touches key material: the key reference
   lives only in runner env; the parser REFUSES to record any output
   containing key markers (tested); SignatureRecord/ProvenanceRecord rows
   carry references + integrity hashes only (grep-style test asserts
   `-----BEGIN` never persists).
3. **Artifact identity = immutable digest, NEVER a tag** (Section 8; tested
   directly): `compute_artifact_digest` accepts only `sha256:<64hex>` from
   real build output (`docker inspect --format '{{.Id}}'`, captured by the
   compiled container.build command into image-digest.txt); a tag-shaped
   input raises `TagOnlyDigestError` before any write.
4. **EvidenceModel.artifacts / .attestations are no longer permanently empty
   (confirmation).** `ArtifactRecord` (digest, registry host, sbom_ref,
   signature_ref), `SignatureRecordRow` and `ProvenanceRecordRow` (migration
   0005) feed `EvidenceModel.artifacts` / `.attestations`; verified end-to-end
   by the mocked Phase A→B run asserting the compliance view carries the real
   digest, SBOM pointer, signature pointer and both attestation kinds.
5. **Publish is dispatched in TWO waves** (Section 5.2 Stage 8 "Push only
   after required gates pass"): wave 1 = build…sign_attest; the control plane
   then evaluates `publish_gate` (security_policy + artifact_policy, live
   OPA) on REAL facts — parsed Trivy findings + artifact facts where
   `has_signature` reflects a REAL verification result, not a claim. Only a
   PASS/WAIVED dispatches wave 2 (publish + record_evidence) — the push job
   physically does not exist until the gate passes.
6. **Base-image enforcement is a real Planner check** (not documentation):
   `StageDefinition.base_image` (new optional field) declares the Dockerfile
   base; an undeclared or non-allowlisted base raises `UnapprovedToolError`
   at planning time (reusing Batch 3's exception type per the batch spec).
   The new Phase B job images (docker:27.3.1-cli, syft, trivy, cosign) were
   added to the governed build/tool policies; deny-by-default is unchanged.
7. **Registry allowlist scope = registry HOST.** Artifact facts record the
   host portion ("ghcr.io") of the spec's artifact destination so the rego's
   exact-match allowlist behaves correctly; the compiled publish command
   pushes to `$CI_AGENT_PUBLISH_REF`, a repo CONFIGURATION variable injected
   as a name binding — never a secret (the compiler HARD-FAILS if the
   generated YAML references the secrets context; tested).
8. **Coverage convention extended (Batch 4's ci-agent-results.json):** rows
   may carry `coverage_percent`; `PhaseBOrchestrator` compares it with
   `PipelineSpec.thresholds["coverage_percent"]` (the Batch 1 field, now
   wired) — fail-closed when the data is missing but a threshold exists.
9. **Exception storage = DB table** (Task D allowed file or DB): `exception_
   records` (migration 0005), because exceptions must be read
   transactionally by the PDP and audited like all control-plane state;
   `governance/catalog/policies/exceptions/README.md` records the decision
   and `governance/schemas/exception_record.schema.json` governs the
   serialized form. `expires_at` is NOT NULL (Section 18 non-negotiable);
   expiry is derived from the clock at read time (no cleanup job needed for
   correctness — `expire_due_exceptions` is hygiene only).
10. **PDP waiver semantics (conservative):** a FAIL becomes WAIVED only when
    EVERY failed family is covered; for security_policy every failing rule
    must be covered (rule-scoped exceptions cover exactly their rule;
    wildcards cover the family). A partial waiver still FAILS. Waived
    decisions record exception ids in the audit event AND
    `policy_decision_records.exception_ids_json`, and the compliance view
    surfaces `exception_ids` per decision (Section 9: waiver ID/approver
    visible, never collapsed into a pass). No write path exists outside
    `ExceptionService.grant_exception` — enforced by an inspection test
    (Section 7.3 "Policy bypass").
11. **Trivy severity map** (documented non-1:1): CRITICAL/HIGH/MEDIUM/LOW
    1:1; UNKNOWN → MEDIUM (same rationale as pip-audit's unscorable
    published vulnerabilities).
12. **Phase B trigger:** Phase A's approved merge decision is the ONLY
    gateway (`RunState.MERGE_DECISION_PUBLISHED → BUILT`); Phase A calls the
    wired `on_phase_a_approved` callback, and `PhaseBOrchestrator.start`
    re-verifies BOTH the run state AND the audited `approved` flag — a
    failed/rejected Phase A can never start Phase B (tested directly).
    A Phase B start failure after publication is audited
    (`phase_b_start_failed`) without corrupting the published Phase A
    decision; `PhaseBOrchestrator.start` can re-drive it.

## Batch 7 gate results

- Full suite: **558 passed, 1 skipped** (live-credential dispatch; OPA live).
- ruff / black / mypy clean; governance validation 11/11; Alembic 0005
  up/down/up verified.
- DoD evidence: mocked Phase A→B run populates the compliance report with
  real artifact/SBOM/signature data; the exception demonstration prints
  fail → waived(id) → fail-again; base-image, signing-required-but-
  unverifiable and image-vulnerability scenarios all demonstrably block
  publish (live OPA).

**Flagged for later batches:** keyless signing (see 2); admin API authn is
still MVP-grade X-Admin-Key (Batch 5 caveat unchanged); `artifact_registry_
client.push` exists for control-plane-driven environments but the compiled
publish job is the normal push path.

---

# Batch 8 Notes — Multi-Runner Scale (GitLab CI + Jenkins adapters, Section 12)

Batch 8 adds two runner adapters on the vendor-neutral `RunnerAdapter` seam so
one control plane drives GitHub Actions, GitLab CI and Jenkins. Everything
below references the production architecture report: Section 12 (adapters,
never provider logic in the control plane), Section 7.3 (allow-listed command
templates verbatim), Section 10 (timeouts/retries/structured evidence).

## Decisions requiring documentation

1. **Routing is profile-driven and fail-closed (no fallback).**
   `EXECUTION_LOCATION_TO_PROVIDER = {github_hosted: github_actions,
   gitlab_hosted: gitlab_ci, jenkins_self_hosted: jenkins}`. Resolution order:
   persisted `RunRecord.runner_provider` first (a run never migrates runners
   mid-flight), else the project profile's `execution_location`, else
   `UnknownRunnerProviderError` — the router never falls back to another
   runner. An unknown/unregistered provider raises before any adapter call.
2. **Per-provider failure isolation.** The `AdapterRouter` keeps one circuit
   breaker per runner provider (app wiring: threshold 5 / recovery 60 s). An
   open breaker on GitLab raises typed `RunnerUnavailableError` for GitLab
   runs only; GitHub/Jenkins dispatches are unaffected (regression-tested).
   `BreakerOpenError` is translated at the router boundary so control-plane
   code never sees breaker internals.
3. **`DispatchRef.provider` added.** The dispatch ref now stamps the
   originating provider (vendor-neutral registry key). The router stamps it
   via `model_copy` when the adapter leaves it unset, and the Phase A
   orchestrator persists it to `RunRecord.runner_provider` (migration 0006,
   composite index `(runner_provider, external_run_id)` for webhook lookups).
   Signature extension only — existing call sites compile unchanged.
4. **GitLab pipeline creation is synchronous.** `create_pipeline` returns the
   pipeline id in one call, so GitLab dispatch = create branch
   (`ci-agent/<run_id>`, pinned to `source_sha`) → commit `.gitlab-ci.yml` →
   create pipeline; `external_run_id` = pipeline id, no polling loop at
   dispatch time (unlike GitHub's run-by-ref resolution).
5. **GitLab workflow rules deny push-triggered pipelines.** The compiled
   `.gitlab-ci.yml` carries `workflow: rules` that never run on `push` /
   `parent_pipeline` / `pipeline` events and runs the default branch manual
   only — ci-agent pipelines must be created by the adapter (via API), never
   by a developer push (fail-closed ingress discipline).
6. **Jenkins pipeline shape: topological-sequential.** The declarative
   Jenkinsfile emits stages in topological stage order as a single sequence
   (no parallel matrix), because declarative `parallel` stages cannot express
   the cross-stage `needs:` edges GitHub's matrix needs without duplicating
   gate logic. Deviation from the GitHub matrix layout, semantics preserved;
   regression-tested order assertions.
7. **Jenkins artifact delivery is operator-provisioned — FLAGGED.** The
   compiled Jenkinsfile is committed to the *job's* SCM by the operator (the
   Jenkins API surface for job/config provisioning is out of Batch 8 scope;
   Section 12 keeps the control plane out of runner administration). Build
   parameters carry `CI_AGENT_RUN_ID` / `CI_AGENT_PIPELINE_HASH` /
   `CI_AGENT_SOURCE_SHA` for correlation; scan artifacts are archived under
   `ci-agent-scan-<stage_id>/` and fetched via the build artifacts API.
   **Follow-up:** an operator runbook (or job-seed plugin step) must exist
   before production Jenkins use.
8. **GitLab scan evidence = job artifacts zip.** `download_stage_scan_artifact`
   fetches the `stage-<stage_id>` job's artifact archive and extracts
   `*.json` report files (same report contract `ci-agent-scan-<stage_id>` /
   `REPORT_UPLOAD_STAGES` as GitHub; `artifacts: when: always` so failed
   scans still deliver evidence).
9. **Jenkins stage ids are Jenkins stage names.** Stage status comes from
   `wfapi/describe` (stage granularity); the compiler names stages exactly
   `stage-<stage_id>` so observer correlation is symmetrical with GitHub's
   check-run names. Queue → build resolution is bounded (5 attempts,
   exponential backoff) and maps to `RunnerUnavailableError` on exhaustion.
10. **Status mapping tables are explicit and fail-closed (unknown → FAILED).**
    GitLab: success→passed; failed→failed; canceled/cancelled→cancelled;
    skipped→skipped; manual→pending; created/waiting_for_resource/preparing/
    scheduled→queued; pending→pending; running→running; anything else→FAILED.
    Jenkins: SUCCESS→passed; FAILURE/UNSTABLE→failed; ABORTED→cancelled;
    NOT_BUILT→skipped; PAUSED→pending; SKIPPED_FOR_FAILURE→skipped; build
    result UNSTABLE→failed (flaky = not passing); `building:true`→running.
    Every non-1:1 entry is documented here per the Batch 6 invariant.
11. **Webhook isolation.** `POST /webhooks/gitlab` resolves runs by
    `runner_provider == 'gitlab_ci' AND external_run_id == pipeline_id` — a
    payload for another pipeline, or for a GitHub run, is ignored (tested).
    Auth: `X-GITLAB-TOKEN` constant-time compare; unset token ⇒ everything
    rejected (fail-closed). Non-terminal job statuses are not forwarded to
    the orchestrator. Only `Job Hook` events with job name `stage-<stage_id>`
    correlate.
12. **Adapter registration is capability-gated.** The GitLab adapter is
    registered only when `GITLAB_TOKEN` + `GITLAB_PROJECT_ID` are configured;
    Jenkins only when `JENKINS_URL` + `JENKINS_USER` + `JENKINS_API_TOKEN`
    are set. Absent credentials ⇒ that provider is simply not offered
    (fail-closed selection), matching the no-mock rule: the suite dispatches
    against recorded-shape fakes only in unit tests; no live-credential
    claims are made.
13. **No credentials in generated pipelines (textual guard).** Both compilers
    scan output for forbidden fragments (`secrets.`, `withCredentials`,
    `$GITLAB_TOKEN`, `PRIVATE-TOKEN`, `glpat-`, ...) and refuse to compile if
    any appear — secrets-context in generated YAML is a compile error,
    identical to the GitHub compiler's guard.

## Batch 8 gate results

- Adapters: 89 passed (gitlab compiler 12 + gitlab adapter 12 +
  jenkins adapter 12 + router 4 + GitHub retained); GitLab webhook
  ingress: 9 passed.
- Full suite: **611 passed, 1 skipped**; ruff / black / mypy clean.
- Governance validation 11/11 (`provider_matrix.yaml` bumped to 1.1.0 with
  `runner_providers: [github_actions, gitlab_ci, jenkins]`).
- Alembic 0006 up/down/up verified on a fresh SQLite database.

**Flagged for later batches:** Jenkins job/SCM provisioning (decision 7);
GitLab "manual" pipeline default means a human must confirm non-ci-agent
runs in the GitLab UI (product decision documented, not a defect);
`REPORT_UPLOAD_STAGES` eslint mapping carry-over from Batch 6 unchanged.
