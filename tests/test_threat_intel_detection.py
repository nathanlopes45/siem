from app import models
from app.detections import detect_threat_intel, THREAT_INTEL_IPS


def test_fires_on_known_malicious_ip(db_session, make_host, make_log):
    host = make_host()
    known_bad_ip = next(iter(THREAT_INTEL_IPS))
    make_log(host.id, event_type="failed_password", attacker_ip=known_bad_ip)

    detect_threat_intel(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id, models.Alert.alert_type == "Threat Intel Match"
    ).all()
    assert len(alerts) == 1
    assert known_bad_ip in alerts[0].description


def test_does_not_fire_on_unknown_ip(db_session, make_host, make_log):
    host = make_host()
    make_log(host.id, event_type="failed_password", attacker_ip="203.0.113.5")  # not on the list

    detect_threat_intel(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(models.Alert.host_id == host.id).all()
    assert len(alerts) == 0


def test_single_ip_produces_single_alert_regardless_of_log_count(db_session, make_host, make_log):
    """Threat intel match should fire once per IP, not once per matching log line."""
    host = make_host()
    known_bad_ip = next(iter(THREAT_INTEL_IPS))
    for _ in range(5):
        make_log(host.id, event_type="failed_password", attacker_ip=known_bad_ip)

    detect_threat_intel(db_session, host.id)

    alerts = db_session.query(models.Alert).filter(
        models.Alert.host_id == host.id, models.Alert.alert_type == "Threat Intel Match"
    ).all()
    assert len(alerts) == 1