"""
Tests for detect_bruteforce (both the all-time and rapid/windowed variant).
"""

from app import models
from app.detections import detect_bruteforce, BRUTEFORCE_THRESHOLD


def test_fires_at_threshold(db_session, make_host, make_log):
    host = make_host()
    for _ in range(BRUTEFORCE_THRESHOLD):
        make_log(host.id, event_type="failed_password", attacker_ip="1.2.3.4")

    detect_bruteforce(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id, models.Alert.alert_type == "Brute Force Attempt"
    ).all()
    assert len(alerts) == 1
    assert "1.2.3.4" in alerts[0].description


def test_does_not_fire_below_threshold(db_session, make_host, make_log):
    host = make_host()
    for _ in range(BRUTEFORCE_THRESHOLD - 1):
        make_log(host.id, event_type="failed_password", attacker_ip="1.2.3.4")

    detect_bruteforce(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id, models.Alert.alert_type == "Brute Force Attempt"
    ).all()
    assert len(alerts) == 0


def test_ignores_non_failed_password_events(db_session, make_host, make_log):
    host = make_host()
    for _ in range(BRUTEFORCE_THRESHOLD):
        make_log(host.id, event_type="accepted_password", attacker_ip="1.2.3.4")

    detect_bruteforce(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(models.Alert.host_id == host.id).all()
    assert len(alerts) == 0


def test_does_not_duplicate_alert_on_rerun(db_session, make_host, make_log):
    host = make_host()
    for _ in range(BRUTEFORCE_THRESHOLD):
        make_log(host.id, event_type="failed_password", attacker_ip="1.2.3.4")

    detect_bruteforce(db_session, host.id)
    detect_bruteforce(db_session, host.id)  # run again, should not create a second alert

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id, models.Alert.alert_type == "Brute Force Attempt"
    ).all()
    assert len(alerts) == 1


def test_different_hosts_are_isolated(db_session, make_host, make_log):
    """A brute force against host A should never create an alert on host B."""
    host_a = make_host()
    host_b = make_host()
    for _ in range(BRUTEFORCE_THRESHOLD):
        make_log(host_a.id, event_type="failed_password", attacker_ip="1.2.3.4")

    detect_bruteforce(db_session, host_a.id)
    detect_bruteforce(db_session, host_b.id)

    assert db_session.query(models.Alert).filter(models.Alert.host_id == host_a.id).count() == 1
    assert db_session.query(models.Alert).filter(models.Alert.host_id == host_b.id).count() == 0


def test_rapid_variant_respects_time_window(db_session, make_host, make_log):
    """
    Logs outside the rapid-detection window shouldn't count toward it, even
    if they'd count toward the all-time detector. We simulate this by
    directly backdating received_at rather than sleeping in the test.
    """
    from datetime import datetime, timedelta

    host = make_host()
    old_time = datetime.utcnow() - timedelta(minutes=10)

    for _ in range(BRUTEFORCE_THRESHOLD):
        log = make_log(host.id, event_type="failed_password", attacker_ip="9.9.9.9")
        log.received_at = old_time
    db_session.commit()

    detect_bruteforce(db_session, host.id, window_minutes=2)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id, models.Alert.alert_type == "Rapid Brute Force"
    ).all()
    assert len(alerts) == 0  # logs are too old to count toward the 2-minute window