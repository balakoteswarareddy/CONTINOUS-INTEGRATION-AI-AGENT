"""Batch 5 migration: run state, approvals, policy decisions, project registry."""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("run_records", sa.Column("current_state", sa.String(length=64), nullable=True))
    op.add_column(
        "run_records", sa.Column("pipeline_spec_ref", sa.String(length=64), nullable=True)
    )

    op.create_table(
        "approval_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("approver", sa.String(length=255), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "policy_decision_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("stage_id", sa.String(length=128), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("policy_family", sa.String(length=64), nullable=True),
        sa.Column("policy_version", sa.String(length=64), nullable=True),
        sa.Column("reasons_json", sa.Text(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "project_profiles",
        sa.Column("project_id", sa.String(length=255), primary_key=True),
        sa.Column("risk_tier", sa.String(length=16), nullable=False),
        sa.Column("language_stack", sa.String(length=64), nullable=False),
        sa.Column("profile_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "pipeline_specs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.String(length=255), nullable=False, index=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False, index=True),
        sa.Column("spec_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("pipeline_specs")
    op.drop_table("project_profiles")
    op.drop_table("policy_decision_records")
    op.drop_table("approval_records")
    op.drop_column("run_records", "pipeline_spec_ref")
    op.drop_column("run_records", "current_state")
