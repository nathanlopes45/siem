from fastapi import FastAPI, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from uuid import UUID
from typing import Optional
from datetime import datetime, timedelta
from .database import engine, get_db
from . import models
from .parsers import parse_log

THREAT_INTEL_IPS = {
    "185.220.101.1",   # TOR exit node
    "45.95.147.120",   # brute force host
    "103.251.167.20"   # botnet IP
}

BRUTEFORCE_THRESHOLD = 5

app = FastAPI(title="Custom SIEM")

models.Base.metadata.create_all(bind=engine)


class LogIngest(BaseModel):
    host_id: UUID
    log_source: str
    raw_log: str


def _create_alert_if_new(db: Session, host_id: UUID, alert_type: str, description: str):
    """Shared duplicate-check + insert, used by every detector."""
    existing = db.query(models.Alert).filter(
        models.Alert.host_id == host_id,
        models.Alert.description == description
    ).first()
    if existing:
        return
    db.add(models.Alert(host_id=host_id, alert_type=alert_type, description=description))
    db.commit()


def detect_bruteforce(db: Session, host_id: UUID, window_minutes: Optional[int] = None):
    """
    Counts failed_password events per source IP, either across all time
    (window_minutes=None) or within a recent window.
    """
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
    """
    Finds IPs with >= threshold failed_password events that also have at
    least one accepted_password event.
    """
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


@app.get("/")
def root():
    return {"status": "SIEM backend running with database connected"}


@app.post("/hosts")
def create_host(hostname: str, ip_address: str, os_type: str, db: Session = Depends(get_db)):
    new_host = models.Host(
        hostname=hostname,
        ip_address=ip_address,
        os_type=os_type
    )
    db.add(new_host)
    db.commit()
    db.refresh(new_host)
    return new_host


@app.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    return db.query(models.Host).all()


@app.post("/logs")
def ingest_log(
    payload: LogIngest,
    db: Session = Depends(get_db)
):
    parsed = parse_log(payload.log_source, payload.raw_log)

    new_log = models.RawLog(
        host_id=payload.host_id,
        log_source=payload.log_source,
        raw_log=payload.raw_log,
        event_type=parsed["event_type"],
        username=parsed["username"],
        attacker_ip=parsed["src_ip"],
        src_port=parsed["src_port"],
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    run_all_detections(db, payload.host_id)

    return new_log


@app.get("/logs")
def get_logs(
    host_id: Optional[UUID] = Query(None),
    log_source: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(models.RawLog)

    if host_id:
        query = query.filter(models.RawLog.host_id == host_id)

    if log_source:
        query = query.filter(models.RawLog.log_source == log_source)

    if event_type:
        query = query.filter(models.RawLog.event_type == event_type)

    logs = query.order_by(models.RawLog.received_at.desc()).all()

    return logs


@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(models.Alert).order_by(models.Alert.created_at.desc()).all()