"""Batch 7 migration: artifact_records + exception_records + waiver column.

- ``artifact_records`` — supply-chain artifacts identified by immutable
  digest (Section 8); SBOM/signature references fill in as stages complete.
- ``signature_records`` / ``provenance_records`` — signature and in-toto/
  SLSA attestation REFERENCES (pointers + integrity hashes; never key
  material, never attestation payloads).
- ``exception_records`` — governed security exceptions (Sections 6 and 18);
  ``expires_at`` is NOT NULL so a permanent waiver can never exist.
- ``policy_decision_records.exception_ids_json`` — the exception ids that
  waived a decision (Section 9: waiver ID/approver visible in evidence).
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifact_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "run_id",
            sa.String(length=64),
            sa.ForeignKey("run_records.run_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("digest", sa.String(length=128), nullable=False, unique=True, index=True),
        sa.Column("registry", sa.String(length=512), nullable=False),
        sa.Column("sbom_ref", sa.Text(), nullable=True),
        sa.Column("signature_ref", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "exception_records",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("project_id", sa.String(length=255), nullable=False, index=True),
        sa.Column("policy_family", sa.String(length=64), nullable=False, index=True),
        sa.Column("rule_id", sa.String(length=128), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("granted_by", sa.String(length=255), nullable=False),
        sa.Column("granted_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.add_column(
        "policy_decision_records",
        sa.Column("exception_ids_json", sa.Text(), nullable=True),
    )
    op.create_table(
        "signature_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "run_id",
            sa.String(length=64),
            sa.ForeignKey("run_records.run_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("artifact_digest", sa.String(length=128), nullable=False, index=True),
        sa.Column("signature_ref", sa.Text(), nullable=False),
        sa.Column("bundle_ref", sa.Text(), nullable=True),
        sa.Column("keyless", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("signed_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "provenance_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "run_id",
            sa.String(length=64),
            sa.ForeignKey("run_records.run_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("artifact_digest", sa.String(length=128), nullable=False, index=True),
        sa.Column("attestation_ref", sa.Text(), nullable=False),
        sa.Column("predicate_type", sa.String(length=255), nullable=False),
        sa.Column("attestation_sha256", sa.String(length=64), nullable=False),
        sa.Column("subject_digest", sa.String(length=128), nullable=False),
        sa.Column("recorded_at", sa.DateTime(), nullable=False),
    )
    op.add_column("run_records", sa.Column("phase_b_branch", sa.String(length=255), nullable=True))
    op.add_column(
        "run_records", sa.Column("phase_b_external_run_id", sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    op.drop_table("provenance_records")
    op.drop_table("signature_records")
    op.drop_column("run_records", "phase_b_external_run_id")
    op.drop_column("run_records", "phase_b_branch")
    op.drop_column("policy_decision_records", "exception_ids_json")
    op.drop_table("exception_records")
    op.drop_table("artifact_records")
