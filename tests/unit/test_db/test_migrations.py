"""Dedicated Alembic migration test (Batch 2 Task A).

Runs `alembic upgrade head` as a subprocess against a fresh temporary SQLite
file and verifies all three tables exist — this is the one test that exercises
the real migration path (unit tests elsewhere use create_all for speed).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import sqlalchemy

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_alembic_upgrade_head_creates_all_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "migration-test.db"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_path}"

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, f"alembic failed:\n{result.stdout}\n{result.stderr}"
    assert db_path.exists()

    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sqlalchemy.inspect(engine)
        tables = set(inspector.get_table_names())
        expected = {"run_records", "audit_log_entries", "processed_deliveries", "alembic_version"}
        assert expected <= tables

        # Spot-check key columns of each table.
        run_columns = {col["name"] for col in inspector.get_columns("run_records")}
        expected_run = {
            "run_id",
            "project_id",
            "repository",
            "trigger_type",
            "source_sha",
            "status",
            "created_at",
            "updated_at",
        }
        assert expected_run <= run_columns
        audit_columns = {col["name"] for col in inspector.get_columns("audit_log_entries")}
        expected_audit = {
            "id",
            "run_id",
            "event_type",
            "payload_json",
            "prev_hash",
            "entry_hash",
            "created_at",
        }
        assert expected_audit <= audit_columns
        delivery_columns = {col["name"] for col in inspector.get_columns("processed_deliveries")}
        assert {"delivery_id", "run_id", "received_at"} <= delivery_columns
    finally:
        engine.dispose()


def test_alembic_upgrade_head_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "migration-idempotent.db"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_path}"

    first = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    second = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert "Running upgrade" not in second.stdout  # nothing left to do
