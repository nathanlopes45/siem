"""
Background detection worker.

Runs as its own container/process, separate from the FastAPI API process.
Polls the database on a fixed interval and runs detection rules for every
host, instead of running detection inline inside the log-ingestion request.

Why this matters: ingestion should stay fast and simple (just validate +
store the log) regardless of how expensive detection logic becomes later
(cross-host correlation, ML scoring, external threat intel lookups, etc).
Decoupling means a slow or failing detector can't block or slow down log
ingestion, and detection can be scaled independently of the API.
"""

import time
import logging

from .database import SessionLocal
from . import models
from .detections import run_all_detections

logging.basicConfig(level=logging.INFO, format="%(asctime)s [worker] %(message)s")
logger = logging.getLogger("siem-worker")

POLL_INTERVAL_SECONDS = 10


def run_detection_cycle():
    db = SessionLocal()
    try:
        host_ids = [row[0] for row in db.query(models.Host.id).distinct().all()]
        for host_id in host_ids:
            run_all_detections(db, host_id)
        logger.info(f"Detection cycle complete — checked {len(host_ids)} host(s)")
    except Exception:
        logger.exception("Detection cycle failed")
    finally:
        db.close()


def main():
    logger.info(f"Worker started, polling every {POLL_INTERVAL_SECONDS}s")
    while True:
        run_detection_cycle()
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()