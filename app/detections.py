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

THREAT_INTEL_IPS = {
    "185.220.101.1",   # TOR exit node
    "45.95.147.120",   # brute force host
    "103.251.167.20"   # botnet IP
}

BRUTEFORCE_THRESHOLD = 5


def _create_alert_if_new(db: Session, host_id: UUID, alert_type: str, description: str):
    existing = db.query(models.Alert).filter(
        models.Alert.host_id == host_id,
        models.Alert.description == description
    ).first()
    if existing:
        return
    db.add(models.Alert(host_id=host_id, alert_type=alert_type, description=description))
    db.commit()


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


def run_all_detections(db: Session, host_id: UUID):
    detect_bruteforce(db, host_id)
    detect_bruteforce(db, host_id, window_minutes=2)
    detect_successful_bruteforce(db, host_id)
    detect_threat_intel(db, host_id)