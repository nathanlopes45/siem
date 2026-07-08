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

GENERIC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_ssh_log(raw_log: str) -> ParsedLog:
    """Parses OpenSSH auth.log-style lines (sshd)."""
    if match := SSH_FAILED_RE.search(raw_log):
        return {
            "event_type": "failed_password",
            "username": match.group("user"),
            "src_ip": match.group("ip"),
            "src_port": int(match.group("port")),
        }

    if match := SSH_ACCEPTED_RE.search(raw_log):
        return {
            "event_type": "accepted_password",
            "username": match.group("user"),
            "src_ip": match.group("ip"),
            "src_port": int(match.group("port")),
        }

    if match := SSH_INVALID_USER_RE.search(raw_log):
        return {
            "event_type": "invalid_user",
            "username": match.group("user"),
            "src_ip": match.group("ip"),
            "src_port": None,
        }

    return _generic_fallback(raw_log)


def _generic_fallback(raw_log: str) -> ParsedLog:
    """Used for unrecognized sources/formats — still grabs an IP if present."""
    match = GENERIC_IP_RE.search(raw_log)
    return {
        "event_type": "unknown",
        "username": None,
        "src_ip": match.group(0) if match else None,
        "src_port": None,
    }


# Map a declared log_source to its parser. Add new sources here.
PARSERS = {
    "sshd": parse_ssh_log,
    "ssh": parse_ssh_log,
    "auth": parse_ssh_log,
}


def parse_log(log_source: str, raw_log: str) -> ParsedLog:
    parser = PARSERS.get(log_source.lower(), _generic_fallback)
    return parser(raw_log)