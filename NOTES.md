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
