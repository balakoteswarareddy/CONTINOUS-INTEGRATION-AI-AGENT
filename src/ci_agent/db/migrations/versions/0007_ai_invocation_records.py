"""Batch 9 migration: AI invocation records (Section 13 Phase 4).

Creates ``ai_invocation_records`` — one row per model-gateway invocation
regardless of outcome, carrying sha256 prompt/response HASHES (never the
content itself; the prompt may contain confidential source code). ``run_id``
is nullable: intake normalization and design-time pipeline explanation are
not run-scoped.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_invocation_records",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column(
            "run_id",
            sa.String(length=64),
            sa.ForeignKey("run_records.run_id"),
            nullable=True,
        ),
        sa.Column("feature", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("context_classification", sa.String(length=32), nullable=False),
        sa.Column("prompt_hash", sa.String(length=80), nullable=False),
        sa.Column("response_hash", sa.String(length=80), nullable=False),
        sa.Column("tokens_used", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("fallback_used", sa.Boolean(), nullable=False),
        sa.Column("policy_allowed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_ai_invocation_records_run_id"), "ai_invocation_records", ["run_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_ai_invocation_records_run_id"), table_name="ai_invocation_records")
    op.drop_table("ai_invocation_records")
