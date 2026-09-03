"""Shared pytest fixtures for the CI Agent test suite."""

from __future__ import annotations

import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from ci_agent.audit.audit_store import AuditStore
from ci_agent.db.base import Base, create_engine, get_session_factory


@pytest.fixture()
def memory_engine() -> Engine:
    """A fresh in-memory SQLite engine with all tables created (fast unit tests)."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def session_factory(memory_engine: Engine) -> sessionmaker:
    return get_session_factory(memory_engine)


@pytest.fixture()
def audit_store(session_factory) -> AuditStore:
    return AuditStore(session_factory)
