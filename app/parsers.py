"""
Log parsing layer.

Takes raw log text plus a declared log_source and extracts structured
fields (event_type, username, src_ip, src_port) instead of treating the
log as an opaque string. Detection rules query these structured fields,
which is both more accurate and lets the database use indexes properly
instead of a leading-wildcard ilike scan.

Adding a new source format = add a new parser function + one line in
the dispatch table at the bottom.
"""

import re
from typing import Optional, TypedDict


class ParsedLog(TypedDict):
    event_type: str
    username: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[int]
    http_status: Optional[int]
    http_path: Optional[str]
    http_method: Optional[str]


IP_PATTERN = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"

SSH_FAILED_RE = re.compile(
    rf"Failed password for (?:invalid user )?(?P<user>\S+) from {IP_PATTERN} port (?P<port>\d+)",
    re.IGNORECASE,
)
SSH_ACCEPTED_RE = re.compile(
    rf"Accepted password for (?P<user>\S+) from {IP_PATTERN} port (?P<port>\d+)",
    re.IGNORECASE,
)
SSH_INVALID_USER_RE = re.compile(
    rf"Invalid user (?P<user>\S+) from {IP_PATTERN}",
    re.IGNORECASE,
)

# Apache/Nginx Combined Log Format, e.g.:
# 203.0.113.5 - - [10/Jul/2026:14:32:10 +0000] "GET /wp-admin/ HTTP/1.1" 404 512 "-" "Mozilla/5.0"
WEB_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

GENERIC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_ssh_log(raw_log: str) -> ParsedLog:
    """Parses OpenSSH auth.log-style lines (sshd)."""
    if match := SSH_FAILED_RE.search(raw_log):
        return {
            "event_type": "failed_password",
            "username": match.group("user"),
            "src_ip": match.group("ip"),
            "src_port": int(match.group("port")),
            "http_status": None,
            "http_path": None,
            "http_method": None,
        }

    if match := SSH_ACCEPTED_RE.search(raw_log):
        return {
            "event_type": "accepted_password",
            "username": match.group("user"),
            "src_ip": match.group("ip"),
            "src_port": int(match.group("port")),
            "http_status": None,
            "http_path": None,
            "http_method": None,
        }

    if match := SSH_INVALID_USER_RE.search(raw_log):
        return {
            "event_type": "invalid_user",
            "username": match.group("user"),
            "src_ip": match.group("ip"),
            "src_port": None,
            "http_status": None,
            "http_path": None,
            "http_method": None,
        }

    return _generic_fallback(raw_log)


def parse_web_log(raw_log: str) -> ParsedLog:
    """
    Parses Apache/Nginx Combined Log Format lines. Buckets event_type by
    status class (http_2xx/3xx/4xx/5xx) rather than the exact status code —
    this keeps detection queries as fast indexed equality lookups on
    event_type (same pattern as the SSH parser), while the exact code is
    still preserved separately in http_status for display/detail.
    """
    match = WEB_LOG_RE.search(raw_log)
    if not match:
        return _generic_fallback(raw_log)

    status = int(match.group("status"))
    status_class = status // 100
    event_type = f"http_{status_class}xx" if status_class in (2, 3, 4, 5) else "http_other"

    return {
        "event_type": event_type,
        "username": None,
        "src_ip": match.group("ip"),
        "src_port": None,
        "http_status": status,
        "http_path": match.group("path"),
        "http_method": match.group("method"),
    }


def _generic_fallback(raw_log: str) -> ParsedLog:
    """Used for unrecognized sources/formats — still grabs an IP if present."""
    match = GENERIC_IP_RE.search(raw_log)
    return {
        "event_type": "unknown",
        "username": None,
        "src_ip": match.group(0) if match else None,
        "src_port": None,
        "http_status": None,
        "http_path": None,
        "http_method": None,
    }


# Map a declared log_source to its parser. Add new sources here.
PARSERS = {
    "sshd": parse_ssh_log,
    "ssh": parse_ssh_log,
    "auth": parse_ssh_log,
    "nginx": parse_web_log,
    "apache": parse_web_log,
    "web": parse_web_log,
    "access": parse_web_log,
}


def parse_log(log_source: str, raw_log: str) -> ParsedLog:
    parser = PARSERS.get(log_source.lower(), _generic_fallback)
    return parser(raw_log)