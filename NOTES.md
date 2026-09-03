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
