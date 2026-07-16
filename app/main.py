from fastapi import FastAPI, Depends, Query, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import func, text
from sqlalchemy.orm import Session
from uuid import UUID
from typing import Optional
from datetime import datetime, timedelta
import os
import json
from .database import engine, get_db
from . import models
from .parsers import parse_log
from .detections import run_all_detections, detect_cross_host_correlation
from .auth import require_api_key
from .triage import generate_triage
from .agent import run_agent_investigation

app = FastAPI(title="Custom SIEM")

models.Base.metadata.create_all(bind=engine)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class LogIngest(BaseModel):
    host_id: UUID
    log_source: str
    raw_log: str


@app.get("/")
def root():
    """Left unauthenticated on purpose, a basic liveness check for
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
        http_status=parsed.get("http_status"),
        http_path=parsed.get("http_path"),
        http_method=parsed.get("http_method"),
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
def get_alerts(limit: Optional[int] = Query(100), db: Session = Depends(get_db)):
    return (
        db.query(models.Alert)
        .order_by(models.Alert.created_at.desc())
        .limit(limit)
        .all()
    )


@app.post("/detect/{host_id}", dependencies=[Depends(require_api_key)])
def trigger_detection(host_id: UUID, db: Session = Depends(get_db)):
    """
    Manual trigger for detection on a single host, useful for testing/demos
    so you don't have to wait for the worker's poll interval. The worker
    still runs this automatically in the background on its own schedule.
    """
    run_all_detections(db, host_id)
    return {"status": f"Detection run complete for host {host_id}"}


@app.post("/detect-cross-host", dependencies=[Depends(require_api_key)])
def trigger_cross_host_detection(db: Session = Depends(get_db)):
    """
    Manual trigger for the fleet-wide cross-host correlation rule. Same
    testing/demo rationale as /detect/{host_id}, the worker runs this
    automatically every cycle regardless.
    """
    detect_cross_host_correlation(db)
    return {"status": "Cross-host correlation detection run complete"}


@app.post("/alerts/{alert_id}/triage", dependencies=[Depends(require_api_key)])
def triage_alert(alert_id: UUID, db: Session = Depends(get_db)):
    """
    LLM-assisted triage: sends the alert plus its related raw log lines to
    Claude and asks for a plain-English summary, a severity rating, and a
    recommended next step. Purely advisory, this never takes action on its
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
    alert.recommended_action = result["recommended_action"]
    db.commit()
    db.refresh(alert)

    return {
        "alert_id": str(alert.id),
        "alert_type": alert.alert_type,
        "triage_summary": alert.triage_summary,
        "severity": alert.severity,
        "recommended_action": alert.recommended_action,
    }


@app.post("/alerts/{alert_id}/investigate", dependencies=[Depends(require_api_key)])
def investigate_alert(alert_id: UUID, db: Session = Depends(get_db)):
    """
    Agentic investigation: unlike /triage (one prompt, one answer), this
    runs a bounded ReAct loop, the model decides which read-only tools to
    call (recent logs, threat intel, cross-host activity, host info),
    observes results, and repeats before concluding. The full reasoning
    trace is persisted to AgentInvestigation for auditability, not just
    the final answer. Falls back to simple triage if the loop can't reach
    a valid conclusion within its iteration cap. See app/agent.py.
    """
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    result = run_agent_investigation(db, alert)

    investigation = models.AgentInvestigation(
        alert_id=alert.id,
        trace=json.dumps(result["trace"]),
        tools_used=json.dumps(result["tools_used"]),
        final_summary=result["summary"],
        final_severity=result["severity"],
        recommended_action=result["recommended_action"],
        key_evidence=json.dumps(result["key_evidence"]),
        iterations=result["iterations"],
        fell_back=result["fell_back"],
    )
    db.add(investigation)

    # Same fields as /triage updates, so the dashboard chip/panel logic
    # doesn't need to know or care whether an alert was assessed by the
    # simple triage path or the full agent path.
    if result["severity"]:
        alert.severity = result["severity"]
    if result["summary"]:
        alert.triage_summary = result["summary"]
    if result["recommended_action"]:
        alert.recommended_action = result["recommended_action"]

    db.commit()
    db.refresh(investigation)

    return {
        "investigation_id": str(investigation.id),
        "alert_id": str(alert.id),
        "summary": result["summary"],
        "severity": result["severity"],
        "recommended_action": result["recommended_action"],
        "key_evidence": result["key_evidence"],
        "tools_used": result["tools_used"],
        "iterations": result["iterations"],
        "fell_back": result["fell_back"],
        "trace": result["trace"],
    }


@app.get("/alerts/{alert_id}/investigations", dependencies=[Depends(require_api_key)])
def get_investigations(alert_id: UUID, db: Session = Depends(get_db)):
    """Returns past agent investigations for an alert, most recent first,
    including the full reasoning trace, used by the dashboard to render
    the "view agent trace" panel."""
    rows = (
        db.query(models.AgentInvestigation)
        .filter(models.AgentInvestigation.alert_id == alert_id)
        .order_by(models.AgentInvestigation.created_at.desc())
        .all()
    )
    return [
        {
            "id": str(r.id),
            "created_at": r.created_at.isoformat(),
            "trace": json.loads(r.trace) if r.trace else [],
            "tools_used": json.loads(r.tools_used) if r.tools_used else [],
            "key_evidence": json.loads(r.key_evidence) if r.key_evidence else [],
            "iterations": r.iterations,
            "fell_back": r.fell_back,
            "final_summary": r.final_summary,
            "final_severity": r.final_severity,
            "recommended_action": r.recommended_action,
        }
        for r in rows
    ]


@app.get("/dashboard")
def dashboard():
    """
    Serves the static dashboard shell. Unauthenticated on purpose, it's
    just HTML/CSS/JS with no data baked in. Every actual data request the
    page makes goes through the normal authenticated JSON endpoints below,
    with the API key entered client-side and never sent anywhere but this
    API.
    """
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.html"))


@app.get("/stats/summary", dependencies=[Depends(require_api_key)])
def stats_summary(db: Session = Depends(get_db)):
    since_24h = datetime.utcnow() - timedelta(hours=24)
    return {
        "total_hosts": db.query(func.count(models.Host.id)).scalar(),
        "total_logs": db.query(func.count(models.RawLog.id)).scalar(),
        "total_alerts": db.query(func.count(models.Alert.id)).scalar(),
        "alerts_last_24h": (
            db.query(func.count(models.Alert.id))
            .filter(models.Alert.created_at >= since_24h)
            .scalar()
        ),
    }


@app.get("/stats/alerts-by-type", dependencies=[Depends(require_api_key)])
def stats_alerts_by_type(db: Session = Depends(get_db)):
    results = (
        db.query(models.Alert.alert_type, func.count().label("count"))
        .group_by(models.Alert.alert_type)
        .order_by(func.count().desc())
        .all()
    )
    return [{"alert_type": t, "count": c} for t, c in results]


@app.get("/stats/log-volume", dependencies=[Depends(require_api_key)])
def stats_log_volume(hours: int = Query(6, ge=1, le=168), db: Session = Depends(get_db)):
    """
    Buckets log ingestion into 10-minute windows over the requested lookback
    period, using Postgres's date_bin (14+) so the bucketing happens in the
    database rather than in a Python loop, same principle as the detection
    engine's aggregation queries.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    bucket = func.date_bin(
        text("'10 minutes'"), models.RawLog.received_at, text("TIMESTAMP '2000-01-01'")
    )
    results = (
        db.query(bucket.label("bucket"), func.count().label("count"))
        .filter(models.RawLog.received_at >= since)
        .group_by(text("bucket"))
        .order_by(text("bucket"))
        .all()
    )
    return [{"bucket": b.isoformat(), "count": c} for b, c in results]


@app.get("/stats/hosts-overview", dependencies=[Depends(require_api_key)])
def stats_hosts_overview(db: Session = Depends(get_db)):
    results = (
        db.query(
            models.Host.id,
            models.Host.hostname,
            func.count(models.RawLog.id).label("log_count"),
            func.max(models.RawLog.received_at).label("last_seen"),
        )
        .outerjoin(models.RawLog, models.RawLog.host_id == models.Host.id)
        .group_by(models.Host.id)
        .order_by(models.Host.hostname)
        .all()
    )
    return [
        {
            "id": str(host_id),
            "hostname": hostname,
            "log_count": log_count,
            "last_seen": last_seen.isoformat() if last_seen else None,
        }
        for host_id, hostname, log_count, last_seen in results
    ]