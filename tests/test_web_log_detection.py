"""
Tests for detect_web_scanning and detect_error_spike, the two detectors
added for web access log support alongside the existing SSH-focused ones.
"""

from app import models
from app.detections import (
    detect_web_scanning,
    detect_error_spike,
    WEB_SCAN_THRESHOLD,
    ERROR_SPIKE_THRESHOLD,
)


def test_web_scanning_fires_at_threshold(db_session, make_host, make_log):
    host = make_host()
    for _ in range(WEB_SCAN_THRESHOLD):
        make_log(host.id, event_type="http_4xx", attacker_ip="9.9.9.9")

    detect_web_scanning(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id,
        models.Alert.alert_type == "Web Reconnaissance (404 Scanning)",
    ).all()
    assert len(alerts) == 1
    assert "9.9.9.9" in alerts[0].description


def test_web_scanning_does_not_fire_below_threshold(db_session, make_host, make_log):
    host = make_host()
    for _ in range(WEB_SCAN_THRESHOLD - 1):
        make_log(host.id, event_type="http_4xx", attacker_ip="9.9.9.9")

    detect_web_scanning(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(models.Alert.host_id == host.id).all()
    assert len(alerts) == 0


def test_web_scanning_ignores_2xx_responses(db_session, make_host, make_log):
    """Legitimate traffic (2xx) should never trip the scanning detector,
    no matter the volume."""
    host = make_host()
    for _ in range(WEB_SCAN_THRESHOLD + 5):
        make_log(host.id, event_type="http_2xx", attacker_ip="9.9.9.9")

    detect_web_scanning(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(models.Alert.host_id == host.id).all()
    assert len(alerts) == 0


def test_error_spike_fires_at_threshold(db_session, make_host, make_log):
    host = make_host()
    for _ in range(ERROR_SPIKE_THRESHOLD):
        make_log(host.id, event_type="http_5xx", attacker_ip="1.2.3.4")

    detect_error_spike(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id,
        models.Alert.alert_type == "Elevated Server Error Rate",
    ).all()
    assert len(alerts) == 1


def test_error_spike_does_not_fire_below_threshold(db_session, make_host, make_log):
    host = make_host()
    for _ in range(ERROR_SPIKE_THRESHOLD - 1):
        make_log(host.id, event_type="http_5xx", attacker_ip="1.2.3.4")

    detect_error_spike(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(models.Alert.host_id == host.id).all()
    assert len(alerts) == 0


def test_error_spike_counts_across_all_ips_not_per_ip(db_session, make_host, make_log):
    """Unlike web scanning, the error spike detector is host-wide, it
    should fire from many DIFFERENT ips each sending a few 5xx, not just
    one IP sending many."""
    host = make_host()
    for i in range(ERROR_SPIKE_THRESHOLD):
        make_log(host.id, event_type="http_5xx", attacker_ip=f"10.0.0.{i}")

    detect_error_spike(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id,
        models.Alert.alert_type == "Elevated Server Error Rate",
    ).all()
    assert len(alerts) == 1