"""
Tests for detect_successful_bruteforce, this is the detector that had a
real bug fixed during development (it used to only check the LAST
successful-login IP seen, silently missing earlier ones). These tests
guard against that regression.
"""

from app import models
from app.detections import detect_successful_bruteforce, BRUTEFORCE_THRESHOLD


def test_fires_when_success_follows_enough_failures(db_session, make_host, make_log):
    host = make_host()
    for _ in range(BRUTEFORCE_THRESHOLD):
        make_log(host.id, event_type="failed_password", attacker_ip="1.2.3.4")
    make_log(host.id, event_type="accepted_password", attacker_ip="1.2.3.4")

    detect_successful_bruteforce(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id, models.Alert.alert_type == "Successful Brute Force"
    ).all()
    assert len(alerts) == 1


def test_does_not_fire_when_success_without_enough_failures(db_session, make_host, make_log):
    host = make_host()
    make_log(host.id, event_type="failed_password", attacker_ip="1.2.3.4")
    make_log(host.id, event_type="accepted_password", attacker_ip="1.2.3.4")

    detect_successful_bruteforce(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(models.Alert.host_id == host.id).all()
    assert len(alerts) == 0


def test_checks_every_successful_ip_not_just_the_last(db_session, make_host, make_log):
    """
    Regression test for the original bug: two different IPs both log in
    successfully. IP A had enough prior failures to qualify; IP B (logged
    in more recently) did not. Both must be evaluated independently.
    """
    host = make_host()

    # IP A: qualifies (enough failures, then success)
    for _ in range(BRUTEFORCE_THRESHOLD):
        make_log(host.id, event_type="failed_password", attacker_ip="1.1.1.1")
    make_log(host.id, event_type="accepted_password", attacker_ip="1.1.1.1")

    # IP B: does NOT qualify (no failures, clean login), logged in after A
    make_log(host.id, event_type="accepted_password", attacker_ip="2.2.2.2")

    detect_successful_bruteforce(db_session, host.id)

    descriptions = [
        a.description for a in
        db_session.query(models.Alert).filter(models.Alert.host_id == host.id).all()
    ]
    assert any("1.1.1.1" in d for d in descriptions)
    assert not any("2.2.2.2" in d for d in descriptions)