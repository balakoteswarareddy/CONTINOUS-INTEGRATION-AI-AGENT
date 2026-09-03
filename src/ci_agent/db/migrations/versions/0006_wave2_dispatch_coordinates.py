"""Batch 8 migration (Batch 7.1 wave-2 hardening, folded in): wave-2 columns.

Covers both folded-in Batch 7.1 fixes:

- **Fix A (spec-drift guard)** — no schema change: the guard is orchestrator
  logic comparing the re-fetched spec hash against the EXISTING
  ``run_records.pipeline_spec_ref`` column (which stops being overwritten
  after its initial write). Recorded here so the migration history documents
  the behavioural change alongside its sibling.
- **Fix B (wave-2 dispatch coordinates)** — adds
  ``run_records.phase_b_wave2_branch`` and
  ``run_records.phase_b_wave2_external_run_id``, matching the naming and
  table of the wave-1 equivalents (``phase_b_branch`` /
  ``phase_b_external_run_id``), so the publish wave's dispatch coordinates
  are queryable from the DB directly and not only from audit payloads.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("run_records", sa.Column("phase_b_wave2_branch", sa.String(length=255)))
    op.add_column("run_records", sa.Column("phase_b_wave2_external_run_id", sa.String(length=64)))


def downgrade() -> None:
    op.drop_column("run_records", "phase_b_wave2_external_run_id")
    op.drop_column("run_records", "phase_b_wave2_branch")
