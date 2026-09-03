# Exception / waiver records — storage location

Task D offered "file-based for MVP, or DB table". Decision: **DB table**
(`exception_records`, migration `0005`), because exceptions must be read
transactionally by the PDP during gate evaluation and audited like every
other control-plane state change — the same reason findings and approvals
live in tables. This directory intentionally holds no record files.

Invariants (Sections 6 and 18 — non-negotiable, tested):

* `expires_at` is NOT NULL — a permanent exception cannot be created;
* the ONLY creation path is `ExceptionService.grant_exception` (admin API
  `POST /admin/exceptions`, same MVP `X-Admin-Key` control as Batch 5);
* the PDP / Planner / orchestrators have no write path (Section 7.3
  "Policy bypass" — enforced by an inspection test);
* expiry is derived from the clock at read time, so exceptions die
  automatically (the `expire_due_exceptions` cleanup is hygiene only).
