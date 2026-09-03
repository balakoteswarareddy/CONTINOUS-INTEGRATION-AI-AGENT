"""Batch 8 migration: run_records.runner_provider.

Which RunnerAdapter owns the run (github_actions | gitlab_ci | jenkins) —
webhook ingestion and reconciliation resolve runs by provider + external ids
(multi-runner scale, Section 12).
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("run_records", sa.Column("runner_provider", sa.String(length=32), nullable=True))
    op.create_index(
        "ix_run_records_provider_external",
        "run_records",
        ["runner_provider", "external_run_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_run_records_provider_external", table_name="run_records")
    op.drop_column("run_records", "runner_provider")
