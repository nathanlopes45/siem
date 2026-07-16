"""
Real syslog ingestion, a UDP listener on port 514 (the standard syslog
port), so this SIEM can receive logs the way a real one does: pushed from
an actual box (e.g. via rsyslog's @@host:514 forwarding, or the `logger`
command), not only hand-crafted JSON POSTed via curl.

Runs as its own container/process, same architectural pattern as
app/worker.py, writes directly to the database rather than going through
the HTTP API, since it's an internal, trusted service on the same Docker
network.

Known simplification (documented honestly rather than hidden): incoming
messages are attributed to a Host by exact match on the UDP packet's
source IP against Host.ip_address. This is fine for a lab/demo setup with
a handful of known hosts, but a production syslog receiver would need
more robust source identification (TLS client certs, structured syslog
headers with a hostname field, etc.).
"""

import os
import socketserver
import logging

from .database import SessionLocal
from . import models
from .parsers import parse_log

logging.basicConfig(level=logging.INFO, format="%(asctime)s [syslog] %(message)s")
logger = logging.getLogger("siem-syslog")

SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
# Which parser to apply to incoming lines. Real syslog auth traffic is
# overwhelmingly SSH/auth in a lab setup like this one, see app/parsers.py
# to add source-specific dispatch if you start forwarding other formats.
DEFAULT_LOG_SOURCE = os.getenv("SYSLOG_DEFAULT_SOURCE", "sshd")


def process_syslog_message(db, client_ip: str, message: str) -> bool:
    """
    Core ingestion logic, separated from the socket-handling plumbing so
    it can be unit tested directly (see tests/test_syslog_listener.py)
    without needing an actual UDP socket. Returns True if the message was
    ingested, False if it was dropped (unregistered source host).
    """
    host = db.query(models.Host).filter(models.Host.ip_address == client_ip).first()
    if not host:
        logger.warning(f"Dropped syslog message from unregistered host {client_ip}: {message[:80]}")
        return False

    parsed = parse_log(DEFAULT_LOG_SOURCE, message)
    new_log = models.RawLog(
        host_id=host.id,
        log_source=DEFAULT_LOG_SOURCE,
        raw_log=message,
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
    logger.info(f"Ingested syslog message from {client_ip} ({host.hostname}): {message[:80]}")
    return True


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw_bytes = self.request[0]
        client_ip = self.client_address[0]
        message = raw_bytes.strip().decode("utf-8", errors="replace")

        db = SessionLocal()
        try:
            process_syslog_message(db, client_ip, message)
        except Exception:
            logger.exception(f"Failed to process syslog message from {client_ip}")
        finally:
            db.close()


def main():
    logger.info(f"Syslog UDP listener starting on 0.0.0.0:{SYSLOG_PORT}")
    with socketserver.UDPServer(("0.0.0.0", SYSLOG_PORT), SyslogUDPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()