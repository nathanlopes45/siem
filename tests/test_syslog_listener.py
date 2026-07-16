"""
Tests for the syslog listener's core ingestion logic (app/syslog_listener.py).
The actual UDP socket plumbing isn't tested here — same philosophy as the
detection/agent tool tests: test the deterministic logic that the socket
handler delegates to, not the I/O itself.
"""

from app import models
from app.syslog_listener import process_syslog_message


def test_ingests_message_from_known_host(db_session, make_host):
    host = make_host()
    # give the host a real, matchable IP for this test
    host.ip_address = "198.51.100.7"
    db_session.commit()

    result = process_syslog_message(
        db_session, "198.51.100.7",
        "Failed password for root from 45.95.147.120 port 4444 ssh2"
    )

    assert result is True
    logs = db_session.query(models.RawLog).filter(models.RawLog.host_id == host.id).all()
    assert len(logs) == 1
    assert logs[0].event_type == "failed_password"
    assert logs[0].attacker_ip == "45.95.147.120"


def test_drops_message_from_unregistered_host(db_session, make_host):
    make_host()  # some host exists, but not with this IP

    result = process_syslog_message(
        db_session, "203.0.113.200",
        "Failed password for root from 45.95.147.120 port 4444 ssh2"
    )

    assert result is False
    assert db_session.query(models.RawLog).count() == 0