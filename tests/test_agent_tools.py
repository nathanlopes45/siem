"""
Tests for the agent's tools (app/agent.py), the read-only functions the
ReAct loop calls. These are pure DB queries, so they're tested directly
and deterministically, same as the detection logic. The LLM reasoning
loop itself is NOT unit tested here, for the same reason detection logic
tests don't call a real LLM: it's nondeterministic. What IS tested is
that every tool returns exactly what it claims to, since the loop's
correctness depends entirely on tools returning accurate data.
"""

from datetime import datetime, timedelta

from app.agent import (
    tool_get_recent_logs,
    tool_check_threat_intel,
    tool_check_cross_host_activity,
    tool_get_host_info,
)
from app.detections import THREAT_INTEL_IPS


def test_get_recent_logs_returns_matching_logs(db_session, make_host, make_log):
    host = make_host()
    make_log(host.id, event_type="failed_password", attacker_ip="1.1.1.1")
    make_log(host.id, event_type="http_4xx", attacker_ip="2.2.2.2")

    result = tool_get_recent_logs(db_session, host_id=str(host.id))
    assert result["count"] == 2


def test_get_recent_logs_filters_by_event_type(db_session, make_host, make_log):
    host = make_host()
    make_log(host.id, event_type="failed_password", attacker_ip="1.1.1.1")
    make_log(host.id, event_type="http_4xx", attacker_ip="2.2.2.2")

    result = tool_get_recent_logs(db_session, host_id=str(host.id), event_type="http_4xx")
    assert result["count"] == 1
    assert "2.2.2.2" in result["logs"][0]


def test_get_recent_logs_respects_limit(db_session, make_host, make_log):
    host = make_host()
    for _ in range(5):
        make_log(host.id, event_type="failed_password", attacker_ip="1.1.1.1")

    result = tool_get_recent_logs(db_session, host_id=str(host.id), limit=3)
    assert result["count"] == 3


def test_check_threat_intel_true_for_known_ip(db_session):
    known_ip = next(iter(THREAT_INTEL_IPS))
    result = tool_check_threat_intel(db_session, ip=known_ip)
    assert result["is_known_malicious"] is True


def test_check_threat_intel_false_for_unknown_ip(db_session):
    result = tool_check_threat_intel(db_session, ip="203.0.113.99")
    assert result["is_known_malicious"] is False


def test_check_cross_host_activity_counts_distinct_hosts(db_session, make_host, make_log):
    host_a = make_host()
    host_b = make_host()
    make_log(host_a.id, event_type="failed_password", attacker_ip="7.7.7.7")
    make_log(host_b.id, event_type="failed_password", attacker_ip="7.7.7.7")

    result = tool_check_cross_host_activity(db_session, ip="7.7.7.7")
    assert result["distinct_hosts_hit"] == 2


def test_check_cross_host_activity_respects_window(db_session, make_host, make_log):
    host = make_host()
    log = make_log(host.id, event_type="failed_password", attacker_ip="7.7.7.7")
    log.received_at = datetime.utcnow() - timedelta(minutes=120)
    db_session.commit()

    result = tool_check_cross_host_activity(db_session, ip="7.7.7.7", window_minutes=60)
    assert result["distinct_hosts_hit"] == 0


def test_get_host_info_returns_host_details(db_session, make_host):
    host = make_host()
    result = tool_get_host_info(db_session, host_id=str(host.id))
    assert result["hostname"] == host.hostname
    assert result["os_type"] == "linux"


def test_get_host_info_handles_missing_host(db_session):
    result = tool_get_host_info(db_session, host_id="00000000-0000-0000-0000-000000000000")
    assert "error" in result