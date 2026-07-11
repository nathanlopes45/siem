from fastapi import FastAPI, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from uuid import UUID
from typing import Optional
from .database import engine, get_db
from . import models
from .parsers import parse_log
from .detections import run_all_detections, detect_cross_host_correlation
from .auth import require_api_key
from .triage import generate_triage

app = FastAPI(title="Custom SIEM")

models.Base.metadata.create_all(bind=engine)


class LogIngest(BaseModel):
    host_id: UUID
    log_source: str
    raw_log: str


@app.get("/")
def root():
    """Left unauthenticated on purpose — a basic liveness check for
    orchestration/monitoring tools shouldn't require a secret."""
    return {"status": "SIEM backend running with database connected"}


@app.post("/hosts", dependencies=[Depends(require_api_key)])
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


@app.get("/hosts", dependencies=[Depends(require_api_key)])
def list_hosts(db: Session = Depends(get_db)):
    return db.query(models.Host).all()


@app.post("/logs", dependencies=[Depends(require_api_key)])
def ingest_log(
    payload: LogIngest,
    db: Session = Depends(get_db)
):
    """
    Fast path only: parse structured fields and store the log. Detection
    runs separately in the background worker (app/worker.py), on its own
    polling interval, so a slow or growing set of detection rules can
    never add latency to log ingestion.
    """
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

    return new_log


@app.get("/logs", dependencies=[Depends(require_api_key)])
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


@app.get("/alerts", dependencies=[Depends(require_api_key)])
def get_alerts(db: Session = Depends(get_db)):
    return db.query(models.Alert).order_by(models.Alert.created_at.desc()).all()


@app.post("/detect/{host_id}", dependencies=[Depends(require_api_key)])
def trigger_detection(host_id: UUID, db: Session = Depends(get_db)):
    """
    Manual trigger for detection on a single host — useful for testing/demos
    so you don't have to wait for the worker's poll interval. The worker
    still runs this automatically in the background on its own schedule.
    """
    run_all_detections(db, host_id)
    return {"status": f"Detection run complete for host {host_id}"}


@app.post("/detect-cross-host", dependencies=[Depends(require_api_key)])
def trigger_cross_host_detection(db: Session = Depends(get_db)):
    """
    Manual trigger for the fleet-wide cross-host correlation rule. Same
    testing/demo rationale as /detect/{host_id} — the worker runs this
    automatically every cycle regardless.
    """
    detect_cross_host_correlation(db)
    return {"status": "Cross-host correlation detection run complete"}


@app.post("/alerts/{alert_id}/triage", dependencies=[Depends(require_api_key)])
def triage_alert(alert_id: UUID, db: Session = Depends(get_db)):
    """
    LLM-assisted triage: sends the alert plus its related raw log lines to
    Claude and asks for a plain-English summary, a severity rating, and a
    recommended next step. Purely advisory — this never takes action on its
    own, it only writes the summary/severity back onto the alert for a
    human to read. Triggered on demand rather than automatically on every
    alert, to keep LLM API usage opt-in and predictable.
    """
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    logs_query = db.query(models.RawLog.raw_log)
    if alert.host_id:
        logs_query = logs_query.filter(models.RawLog.host_id == alert.host_id)
    related_logs = [
        row[0] for row in
        logs_query.order_by(models.RawLog.received_at.desc()).limit(20).all()
    ]

    result = generate_triage(alert.alert_type, alert.description, related_logs)

    if result["error"]:
        raise HTTPException(status_code=502, detail=f"Triage failed: {result['error']}")

    alert.triage_summary = result["summary"]
    alert.severity = result["severity"]
    db.commit()
    db.refresh(alert)

    return {
        "alert_id": str(alert.id),
        "alert_type": alert.alert_type,
        "triage_summary": alert.triage_summary,
        "severity": alert.severity,
        "recommended_action": result["recommended_action"],
    }