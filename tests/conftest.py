"""
Shared pytest fixtures.

Tests run against a real Postgres database (not mocks) — the detectors'
whole job is correct SQL aggregation (GROUP BY/HAVING, distinct counts),
so mocking the ORM would test nothing meaningful. Each test gets a fresh
schema, created and torn down per test function, so tests never interfere
with each other or with your dev data.

Requires TEST_DATABASE_URL to point at a Postgres instance reachable from
wherever pytest runs (see README for the docker compose exec invocation).
"""

import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models

TEST_DB_NAME = "siem_test_db"


def _resolve_test_database_url() -> str:
    """
    Prefer an explicit TEST_DATABASE_URL if set. Otherwise, derive one from
    the real DATABASE_URL (same host/credentials, different db name) so
    tests automatically work inside the api container without needing
    separate test credentials configured anywhere.
    """
    explicit = os.getenv("TEST_DATABASE_URL")
    if explicit:
        return explicit

    real_url = os.getenv("DATABASE_URL")
    if real_url:
        base, _, _real_db_name = real_url.rpartition("/")
        return f"{base}/{TEST_DB_NAME}"

    raise RuntimeError(
        "Neither TEST_DATABASE_URL nor DATABASE_URL is set — cannot determine "
        "which database to run tests against."
    )


TEST_DATABASE_URL = _resolve_test_database_url()


@pytest.fixture(scope="function")
def db_session():
    engine = create_engine(TEST_DATABASE_URL)
    models.Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        models.Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def make_host(db_session):
    """Factory fixture: make_host() -> a persisted Host, unique each call."""
    def _make_host():
        host = models.Host(
            hostname=f"test-host-{uuid.uuid4().hex[:8]}",
            ip_address="10.0.0.1",
            os_type="linux",
        )
        db_session.add(host)
        db_session.commit()
        db_session.refresh(host)
        return host
    return _make_host


@pytest.fixture
def make_log(db_session):
    """Factory fixture for inserting a RawLog with sensible defaults."""
    def _make_log(host_id, event_type="failed_password", attacker_ip="45.95.147.120",
                  username="root", src_port=4444, log_source="sshd"):
        log = models.RawLog(
            host_id=host_id,
            log_source=log_source,
            raw_log=f"{event_type} for {username} from {attacker_ip} port {src_port} ssh2",
            event_type=event_type,
            username=username,
            attacker_ip=attacker_ip,
            src_port=src_port,
        )
        db_session.add(log)
        db_session.commit()
        return log
    return _make_log