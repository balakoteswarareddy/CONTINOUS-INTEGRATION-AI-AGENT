"""Ingress / Trigger Gateway (Batch 2, Stage 5; Report Section 4.2).

Receives SCM webhook events, validates signature / event type / replay /
repository+branch allowlists, issues a unique run ID, and records every step
(including rejections) to the Audit Store. This batch's job ends at "run
accepted, evidence recorded" — no checkout, lint, or execution.
"""
