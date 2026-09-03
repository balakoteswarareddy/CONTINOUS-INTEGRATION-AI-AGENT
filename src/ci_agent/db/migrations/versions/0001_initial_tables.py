"""Initial tables: run_records, audit_log_entries, processed_deliveries

Revision ID: 0001
Revises:
Create Date: 2026-09-03

Batch 2 Task A — creates the three audit-store tables. Column definitions
mirror src/ci_agent/db/models.py exactly (keep them in sync).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "run_records",
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("project_id", sa.String(length=255), nullable=False),
        sa.Column("repository", sa.String(length=512), nullable=False),
        sa.Column("trigger_type", sa.String(length=32), nullable=False),
        sa.Column("source_sha", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("run_id"),
    )
    op.create_index(op.f("ix_run_records_project_id"), "run_records", ["project_id"], unique=False)

    op.create_table(
        "audit_log_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_audit_log_entries_run_id"), "audit_log_entries", ["run_id"], unique=False
    )

    op.create_table(
        "processed_deliveries",
        sa.Column("delivery_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=True),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("delivery_id"),
    )


def downgrade() -> None:
    op.drop_table("processed_deliveries")
    op.drop_index(op.f("ix_audit_log_entries_run_id"), table_name="audit_log_entries")
    op.drop_table("audit_log_entries")
    op.drop_index(op.f("ix_run_records_project_id"), table_name="run_records")
    op.drop_table("run_records")
