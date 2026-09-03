"""Batch 4: stage_execution_records + run dispatch tracking columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-03

Adds:
- ``stage_execution_records`` (Execution Observer, Stage 10)
- ``run_records.dispatch_branch`` / ``run_records.external_run_id``
  (runner-adapter dispatch tracking; branch convention ci-agent/<run_id>)
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("run_records", sa.Column("dispatch_branch", sa.String(length=255), nullable=True))
    op.add_column("run_records", sa.Column("external_run_id", sa.String(length=64), nullable=True))
    op.create_table(
        "stage_execution_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("stage_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("logs_ref", sa.Text(), nullable=True),
        sa.Column("findings_ref", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["run_records.run_id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_stage_execution_records_run_id"),
        "stage_execution_records",
        ["run_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_stage_execution_records_stage_id"),
        "stage_execution_records",
        ["stage_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_stage_execution_records_stage_id"), table_name="stage_execution_records")
    op.drop_index(op.f("ix_stage_execution_records_run_id"), table_name="stage_execution_records")
    op.drop_table("stage_execution_records")
    op.drop_column("run_records", "external_run_id")
    op.drop_column("run_records", "dispatch_branch")
