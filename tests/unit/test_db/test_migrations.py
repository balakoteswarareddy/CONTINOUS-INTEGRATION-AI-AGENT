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
        expected = {
            "run_records",
            "audit_log_entries",
            "processed_deliveries",
            "alembic_version",
            # Batch 9: AI invocation log (hashes only, never content).
            "ai_invocation_records",
        }
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
            # Batch 8 (folded-in Batch 7.1 Fix B): wave-2 dispatch coordinates.
            "phase_b_wave2_branch",
            "phase_b_wave2_external_run_id",
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
        ai_columns = {col["name"] for col in inspector.get_columns("ai_invocation_records")}
        expected_ai = {
            "id",
            "run_id",
            "feature",
            "provider",
            "context_classification",
            "prompt_hash",
            "response_hash",
            "tokens_used",
            "latency_ms",
            "fallback_used",
            "policy_allowed",
            "created_at",
        }
        assert expected_ai <= ai_columns
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


def _run_alembic(db_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_path}"
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_migration_0006_up_down_up(tmp_path: Path) -> None:
    """Batch 8 migration 0006: wave-2 columns survive up/down/up verified."""
    db_path = tmp_path / "migration-0006.db"

    up = _run_alembic(db_path, "upgrade", "head")
    assert up.returncode == 0, f"upgrade head failed:\n{up.stdout}\n{up.stderr}"

    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sqlalchemy.inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("run_records")}
        assert {"phase_b_wave2_branch", "phase_b_wave2_external_run_id"} <= columns
    finally:
        engine.dispose()

    down = _run_alembic(db_path, "downgrade", "0005")
    assert down.returncode == 0, f"downgrade 0006 failed:\n{down.stdout}\n{down.stderr}"
    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sqlalchemy.inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("run_records")}
        assert "phase_b_wave2_branch" not in columns
        assert "phase_b_wave2_external_run_id" not in columns
    finally:
        engine.dispose()

    up_again = _run_alembic(db_path, "upgrade", "head")
    assert up_again.returncode == 0, f"re-upgrade failed:\n{up_again.stdout}\n{up_again.stderr}"
    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sqlalchemy.inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("run_records")}
        assert {"phase_b_wave2_branch", "phase_b_wave2_external_run_id"} <= columns
    finally:
        engine.dispose()


def test_migration_0007_up_down_up(tmp_path: Path) -> None:
    """Batch 9 migration 0007: ai_invocation_records survives up/down/up."""
    db_path = tmp_path / "migration-0007.db"

    up = _run_alembic(db_path, "upgrade", "head")
    assert up.returncode == 0, f"upgrade head failed:\n{up.stdout}\n{up.stderr}"

    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sqlalchemy.inspect(engine)
        assert "ai_invocation_records" in set(inspector.get_table_names())
        assert "ix_ai_invocation_records_run_id" in {
            index["name"] for index in inspector.get_indexes("ai_invocation_records")
        }
    finally:
        engine.dispose()

    down = _run_alembic(db_path, "downgrade", "0006")
    assert down.returncode == 0, f"downgrade 0007 failed:\n{down.stdout}\n{down.stderr}"
    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sqlalchemy.inspect(engine)
        assert "ai_invocation_records" not in set(inspector.get_table_names())
    finally:
        engine.dispose()

    up_again = _run_alembic(db_path, "upgrade", "head")
    assert up_again.returncode == 0, f"re-upgrade failed:\n{up_again.stdout}\n{up_again.stderr}"
    engine = sqlalchemy.create_engine(f"sqlite:///{db_path}")
    try:
        inspector = sqlalchemy.inspect(engine)
        assert "ai_invocation_records" in set(inspector.get_table_names())
    finally:
        engine.dispose()
