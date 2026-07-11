"""
Tests for detect_cross_host_correlation — the one detector that is NOT
scoped to a single host. Most important behaviors to lock down: it must
require the threshold number of DISTINCT hosts (not just distinct log
rows), and it must not fire for an IP concentrated on a single host no
matter how many attempts.
"""

from app import models
from app.detections import detect_cross_host_correlation, CROSS_HOST_HOST_THRESHOLD


def test_fires_when_ip_hits_enough_distinct_hosts(db_session, make_host, make_log):
    hosts = [make_host() for _ in range(CROSS_HOST_HOST_THRESHOLD)]
    for host in hosts:
        make_log(host.id, event_type="failed_password", attacker_ip="7.7.7.7")

    detect_cross_host_correlation(db_session)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.alert_type == "Cross-Host Brute Force"
    ).all()
    assert len(alerts) == 1
    assert alerts[0].host_id is None  # fleet-wide finding, not attributed to one host
    assert "7.7.7.7" in alerts[0].description


def test_does_not_fire_below_distinct_host_threshold(db_session, make_host, make_log):
    hosts = [make_host() for _ in range(CROSS_HOST_HOST_THRESHOLD - 1)]
    for host in hosts:
        make_log(host.id, event_type="failed_password", attacker_ip="7.7.7.7")

    detect_cross_host_correlation(db_session)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.alert_type == "Cross-Host Brute Force"
    ).all()
    assert len(alerts) == 0


def test_many_attempts_on_one_host_does_not_count_as_cross_host(db_session, make_host, make_log):
    """A volume attack against a single host is a different signal — it
    should never trip the cross-host detector no matter the attempt count."""
    host = make_host()
    for _ in range(20):
        make_log(host.id, event_type="failed_password", attacker_ip="7.7.7.7")

    detect_cross_host_correlation(db_session)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.alert_type == "Cross-Host Brute Force"
    ).all()
    assert len(alerts) == 0