"""Alembic migration environment for the CI Agent audit database (Batch 2).

Reads the database URL from the ``DATABASE_URL`` environment variable when
set, falling back to ``alembic.ini``. ``ci_agent.db.models`` is imported for
its side effect of populating the shared MetaData used by autogenerate.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from ci_agent.db import base as ci_agent_base
from ci_agent.db import models as ci_agent_models  # noqa: F401  (populates Base.metadata)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

_database_url = os.environ.get("DATABASE_URL")
if _database_url:
    config.set_main_option("sqlalchemy.url", _database_url)

target_metadata = ci_agent_base.Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DB connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
