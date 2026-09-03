# Backup & Recovery Notes (Batch 5 — honest operational documentation)

This file documents the CURRENT state of backup/recovery for the ci-agent
control plane. **No backup automation is implemented in the MVP** — the items
below are design notes for pre-production hardening, not claims of working
functionality.

## What exists today

- The control plane's state lives in the configured database
  (`DATABASE_URL`; SQLite file in local/MVP deployments).
- The append-only, hash-chained audit log (`audit_log_entries`) makes
  tampering detectable (`AuditStore.verify_chain`), but it is NOT a backup:
  losing the database loses the audit log with it.
- Pipeline state is reconstructable to a large degree from external systems of
  record: GitHub (dispatch branches, workflow runs, check runs, the
  `ci-agent-results` artifact) and the PDP decision audit trail.

## Pre-production hardening plan (not yet implemented)

1. Automated encrypted database backups (daily full + WAL/point-in-time for
   Postgres) with tested restore drills; retention aligned to the org policy.
2. Object-storage export of audit log segments with the chain anchors stored
   separately, so tamper-evidence survives full database loss.
3. Documented RPO/RTO per environment; backup restore added to the release
   checklist.
4. GitHub App private key + webhook secret + admin key rotation runbook
   (secrets live in the environment/secret manager, never in code — Section 7).

## Explicit non-goals in the MVP

- No cross-region replication, no multi-replica concurrency guard (the
  in-process `ConcurrencyGuard` is single-process by design — NOTES.md).
- No automated disaster-recovery failover.
