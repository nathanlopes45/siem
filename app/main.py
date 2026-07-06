from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session
from uuid import UUID
from typing import Optional
from datetime import datetime, timedelta
from .database import engine, get_db
from . import models
import re

THREAT_INTEL_IPS = {
    "185.220.101.1",   # TOR exit node
    "45.95.147.120",   # brute force host
    "103.251.167.20"   # botnet IP
}

app = FastAPI(title="Custom SIEM")

models.Base.metadata.create_all(bind=engine)

def detect_bruteforce(db: Session, host_id: UUID):

    suspicious_ips = db.query(models.RawLog.attacker_ip).filter(
        models.RawLog.host_id == host_id,
        models.RawLog.raw_log.ilike("%failed password%")
    ).all()

    ip_counts = {}
    for (ip,) in suspicious_ips:
        if ip is None:
            continue
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for ip, count in ip_counts.items():
        if count >= 5:
            existing_alert = db.query(models.Alert).filter(
                models.Alert.host_id == host_id,
                models.Alert.description == f"Brute force attack from {ip}"
            ).first()
            if existing_alert:
                continue
            alert = models.Alert(
                host_id=host_id,
                alert_type="Brute Force Attempt",
                description=f"Brute force attack from {ip}"
            )

            db.add(alert)
            db.commit()


def detect_successful_bruteforce(db: Session, host_id: UUID):

    logs = db.query(models.RawLog).filter(
        models.RawLog.host_id == host_id
    ).all()
    
    ip_attempts = {}
    successful_ip = None
    for log in logs:
        if log.attacker_ip is None:
            continue
        if "failed password" in log.raw_log.lower():
            ip_attempts[log.attacker_ip] = ip_attempts.get(log.attacker_ip, 0) + 1
        if "accepted password" in log.raw_log.lower():
            successful_ip = log.attacker_ip

    if successful_ip and ip_attempts.get(successful_ip, 0) >= 5:
        existing_alert = db.query(models.Alert).filter(
            models.Alert.host_id == host_id,
            models.Alert.description == f"Successful brute force from {successful_ip}"
        ).first()
        if existing_alert:
            return
        alert = models.Alert(
            host_id=host_id,
            alert_type="Successful Brute Force",
            description=f"Successful brute force from {successful_ip}"
        )
        db.add(alert)
        db.commit()


def detect_time_based_bruteforce(db: Session, host_id: UUID):

    two_minutes_ago = datetime.utcnow() - timedelta(minutes=2)
    recent_logs = db.query(models.RawLog).filter(
        models.RawLog.host_id == host_id,
        models.RawLog.raw_log.ilike("%failed password%"),
        models.RawLog.received_at >= two_minutes_ago
    ).all()

    ip_counts = {}

    for log in recent_logs:
        if log.attacker_ip is None:
            continue
        ip_counts[log.attacker_ip] = ip_counts.get(log.attacker_ip, 0) + 1

    for ip, count in ip_counts.items():
        if count >= 5:
            existing_alert = db.query(models.Alert).filter(
                models.Alert.host_id == host_id,
                models.Alert.description == f"Rapid brute force attack from {ip}"
            ).first()
            if existing_alert:
                continue
            alert = models.Alert(
                host_id=host_id,
                alert_type="Rapid Brute Force",
                description=f"Rapid brute force attack from {ip}"
            )
            db.add(alert)
            db.commit()


def detect_threat_intel(db: Session, host_id: UUID):
    logs = db.query(models.RawLog).filter(
        models.RawLog.host_id == host_id
    ).all()
    for log in logs:
        ip = log.attacker_ip
        if ip and ip in THREAT_INTEL_IPS:
            # Prevent duplicate alerts
            existing_alert = db.query(models.Alert).filter(
                models.Alert.host_id == host_id,
                models.Alert.description == f"Known malicious IP {ip} detected"
            ).first()
            if existing_alert:
                continue
            alert = models.Alert(
                host_id=host_id,
                alert_type="Threat Intel Match",
                description=f"Known malicious IP {ip} detected"
            )
            db.add(alert)
            db.commit()


def extract_ip_from_log(log_message: str):
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    match = re.search(ip_pattern, log_message)

    if match:
        return match.group(0)

    return None


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
    host_id: UUID,
    log_source: str,
    raw_log: str,
    db: Session = Depends(get_db)
):
    attacker_ip = extract_ip_from_log(raw_log)
    new_log = models.RawLog(
        host_id=host_id,
        log_source=log_source,
        raw_log=raw_log,
        attacker_ip=attacker_ip
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    # attacker_ip = extract_ip_from_log(raw_log)
    # print("ATTACKER IP:", attacker_ip)

    detect_bruteforce(db, host_id)
    detect_threat_intel(db, host_id)
    detect_successful_bruteforce(db, host_id)
    detect_time_based_bruteforce(db, host_id)
    
    return new_log


@app.get("/logs")
def get_logs(
    host_id: Optional[UUID] = Query(None),
    log_source: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(models.RawLog)

    if host_id:
        query = query.filter(models.RawLog.host_id == host_id)

    if log_source:
        query = query.filter(models.RawLog.log_source == log_source)

    logs = query.order_by(models.RawLog.received_at.desc()).all()

    return logs


@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(models.Alert).order_by(models.Alert.created_at.desc()).all()

