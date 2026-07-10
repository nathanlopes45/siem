"""
Detection engine.

Extracted from main.py so both the API process and the background worker
(app/worker.py) can run the same detection logic without duplicating it.
Detection is deliberately NOT called from the log-ingestion endpoint —
see worker.py for why.
"""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from . import models
from .notifications import send_alert_notification

THREAT_INTEL_IPS = {
    "185.220.101.1",   # TOR exit node
    "45.95.147.120",   # brute force host
    "103.251.167.20"   # botnet IP
}

BRUTEFORCE_THRESHOLD = 5
CROSS_HOST_HOST_THRESHOLD = 3   # distinct hosts an IP must hit to count as cross-host correlation
CROSS_HOST_WINDOW_MINUTES = 30


def _create_alert_if_new(db: Session, host_id: Optional[UUID], alert_type: str, description: str):
    existing = db.query(models.Alert).filter(
        models.Alert.host_id == host_id,
        models.Alert.description == description
    ).first()
    if existing:
        return
    db.add(models.Alert(host_id=host_id, alert_type=alert_type, description=description))
    db.commit()

    # Only fires for genuinely new alerts, never for duplicates — this is
    # what keeps notification volume sane instead of re-pinging on every
    # detection cycle for an attack that's already been alerted on.
    send_alert_notification(alert_type, description, host_id)


def detect_bruteforce(db: Session, host_id: UUID, window_minutes: Optional[int] = None):
    query = db.query(
        models.RawLog.attacker_ip,
        func.count().label("attempt_count")
    ).filter(
        models.RawLog.host_id == host_id,
        models.RawLog.event_type == "failed_password",
        models.RawLog.attacker_ip.isnot(None),
    )

    if window_minutes is not None:
        since = datetime.utcnow() - timedelta(minutes=window_minutes)
        query = query.filter(models.RawLog.received_at >= since)

    results = (
        query.group_by(models.RawLog.attacker_ip)
        .having(func.count() >= BRUTEFORCE_THRESHOLD)
        .all()
    )

    label = "Rapid Brute Force" if window_minutes else "Brute Force Attempt"
    prefix = "Rapid brute force attack from" if window_minutes else "Brute force attack from"

    for ip, count in results:
        _create_alert_if_new(db, host_id, label, f"{prefix} {ip}")


def detect_successful_bruteforce(db: Session, host_id: UUID):
    failed_counts = dict(
        db.query(models.RawLog.attacker_ip, func.count())
        .filter(
            models.RawLog.host_id == host_id,
            models.RawLog.event_type == "failed_password",
            models.RawLog.attacker_ip.isnot(None),
        )
        .group_by(models.RawLog.attacker_ip)
        .all()
    )

    successful_ips = [
        ip for (ip,) in db.query(models.RawLog.attacker_ip)
        .filter(
            models.RawLog.host_id == host_id,
            models.RawLog.event_type == "accepted_password",
            models.RawLog.attacker_ip.isnot(None),
        )
        .distinct()
        .all()
    ]

    for ip in successful_ips:
        if failed_counts.get(ip, 0) >= BRUTEFORCE_THRESHOLD:
            _create_alert_if_new(
                db, host_id, "Successful Brute Force",
                f"Successful brute force from {ip}"
            )


def detect_threat_intel(db: Session, host_id: UUID):
    matches = (
        db.query(models.RawLog.attacker_ip)
        .filter(
            models.RawLog.host_id == host_id,
            models.RawLog.attacker_ip.in_(THREAT_INTEL_IPS),
        )
        .distinct()
        .all()
    )
    for (ip,) in matches:
        _create_alert_if_new(
            db, host_id, "Threat Intel Match",
            f"Known malicious IP {ip} detected"
        )


def detect_cross_host_correlation(db: Session):
    """
    Unlike every other detector, this is NOT scoped to a single host — it
    looks for one source IP with failed_password attempts against multiple
    DISTINCT hosts within a recent window. A single host being brute-forced
    is noisy but common; the same IP hitting 3+ different hosts in 30
    minutes is a much stronger signal of deliberate reconnaissance or
    credential-stuffing across your whole environment (MITRE T1110, with
    lateral-movement / infrastructure-wide targeting context).

    Because this isn't host-scoped, the resulting Alert has host_id=None —
    it's a fleet-wide finding, not a per-host one.
    """
    since = datetime.utcnow() - timedelta(minutes=CROSS_HOST_WINDOW_MINUTES)

    results = (
        db.query(
            models.RawLog.attacker_ip,
            func.count(func.distinct(models.RawLog.host_id)).label("host_count"),
        )
        .filter(
            models.RawLog.event_type == "failed_password",
            models.RawLog.attacker_ip.isnot(None),
            models.RawLog.received_at >= since,
        )
        .group_by(models.RawLog.attacker_ip)
        .having(func.count(func.distinct(models.RawLog.host_id)) >= CROSS_HOST_HOST_THRESHOLD)
        .all()
    )

    for ip, host_count in results:
        _create_alert_if_new(
            db, None, "Cross-Host Brute Force",
            f"IP {ip} attempted failed logins against {host_count} distinct hosts "
            f"within {CROSS_HOST_WINDOW_MINUTES} minutes"
        )


def run_all_detections(db: Session, host_id: UUID):
    detect_bruteforce(db, host_id)
    detect_bruteforce(db, host_id, window_minutes=2)
    detect_successful_bruteforce(db, host_id)
    detect_threat_intel(db, host_id)