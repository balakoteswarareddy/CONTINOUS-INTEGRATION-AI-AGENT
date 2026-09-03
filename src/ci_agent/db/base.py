"""Persistence layer: SQLAlchemy base, engine and session factory (Batch 2).

The engine factory only uses SQLAlchemy-generic configuration so the SQLite
dev database can be swapped for Postgres without code changes (Batch 2 Task A
guardrail: "do NOT hardcode SQLite-only syntax").
"""

from __future__ import annotations

from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Declarative base for all CI Agent ORM models."""


def create_engine(database_url: str) -> Engine:
    """Create a SQLAlchemy engine for ``database_url``.

    SQLite-specific adjustments (thread-check disabling; a shared static pool
    for in-memory databases so all sessions see the same database) are applied
    only when the URL scheme is sqlite; other backends get vanilla settings.
    """
    kwargs: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool
    return sqlalchemy_create_engine(database_url, **kwargs)


def get_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory bound to ``engine``.

    ``expire_on_commit=False`` so ORM objects returned by the AuditStore remain
    readable after the session that loaded them has been closed.
    """
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
