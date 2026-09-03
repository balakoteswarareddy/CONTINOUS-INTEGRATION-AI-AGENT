"""Batch 6 migration: finding_records table for normalized security findings.

The per-stage ``stage_execution_records.findings_ref`` summary column already
existed (reserved since Batch 4) — it is nullable Text, so no DDL change is
needed for it; this migration only adds the FindingRecord detail table.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "run_id",
            sa.String(length=64),
            sa.ForeignKey("run_records.run_id"),
            nullable=False,
            index=True,
        ),
        sa.Column("stage_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("scanner", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("component", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("location", sa.Text(), nullable=True),
        sa.Column("disposition", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("finding_records")
