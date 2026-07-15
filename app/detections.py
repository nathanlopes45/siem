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
WEB_SCAN_THRESHOLD = 10         # 4xx responses from one IP to count as scanning
WEB_SCAN_WINDOW_MINUTES = 5
ERROR_SPIKE_THRESHOLD = 10      # 5xx responses on a host to count as a spike
ERROR_SPIKE_WINDOW_MINUTES = 5


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


def detect_web_scanning(db: Session, host_id: UUID, window_minutes: int = WEB_SCAN_WINDOW_MINUTES):
    """
    One IP generating many HTTP 4xx responses against a host in a short
    window is a classic directory/file brute-forcing signature (tools like
    gobuster/dirbuster/ffuf work exactly this way — requesting a large
    wordlist of paths and watching for anything that isn't a 404).
    MITRE T1595.003 — Active Scanning: Wordlist Scanning.
    """
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    results = (
        db.query(models.RawLog.attacker_ip, func.count().label("count"))
        .filter(
            models.RawLog.host_id == host_id,
            models.RawLog.event_type == "http_4xx",
            models.RawLog.attacker_ip.isnot(None),
            models.RawLog.received_at >= since,
        )
        .group_by(models.RawLog.attacker_ip)
        .having(func.count() >= WEB_SCAN_THRESHOLD)
        .all()
    )
    for ip, count in results:
        _create_alert_if_new(
            db, host_id, "Web Reconnaissance (404 Scanning)",
            f"IP {ip} generated {count} HTTP 4xx responses on this host within "
            f"{window_minutes} minutes — possible directory/file brute-forcing"
        )


def detect_error_spike(db: Session, host_id: UUID, window_minutes: int = ERROR_SPIKE_WINDOW_MINUTES):
    """
    A burst of HTTP 5xx responses on a host is an anomaly worth surfacing,
    but — unlike the other detectors here — it isn't inherently an attack
    signature. It could indicate a denial-of-service attempt, or it could
    just be an application bug or resource exhaustion under legitimate
    load. Framed as "investigate this," not "this is malicious."
    """
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    count = (
        db.query(func.count())
        .filter(
            models.RawLog.host_id == host_id,
            models.RawLog.event_type == "http_5xx",
            models.RawLog.received_at >= since,
        )
        .scalar()
    )
    if count >= ERROR_SPIKE_THRESHOLD:
        _create_alert_if_new(
            db, host_id, "Elevated Server Error Rate",
            f"{count} HTTP 5xx responses on this host within {window_minutes} minutes "
            f"— possible denial-of-service attempt or application fault"
        )


def run_all_detections(db: Session, host_id: UUID):
    detect_bruteforce(db, host_id)
    detect_bruteforce(db, host_id, window_minutes=2)
    detect_successful_bruteforce(db, host_id)
    detect_threat_intel(db, host_id)
    detect_web_scanning(db, host_id)
    detect_error_spike(db, host_id)