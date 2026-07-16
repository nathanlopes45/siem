"""
Outbound alert notifications.

Fires a webhook POST whenever a new alert is created. Works as-is with
Slack Incoming Webhooks (the {"text": ...} payload shape is exactly what
Slack expects); for other targets (Discord, Teams, a custom endpoint),
adjust the payload shape in _build_payload as needed.

Deliberately fails soft: if the webhook URL isn't configured, or the
request fails/times out, we log it and move on. A broken notification
integration should never be able to break the detection engine itself.
"""

import os
import logging
from typing import Optional
from uuid import UUID

import requests

logger = logging.getLogger("siem-notifications")

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")
REQUEST_TIMEOUT_SECONDS = 5


def _build_payload(alert_type: str, description: str, host_id: Optional[UUID]) -> dict:
    scope = f"host {host_id}" if host_id else "fleet-wide"
    return {
        "text": f":rotating_light: *{alert_type}* ({scope})\n{description}"
    }


def send_alert_notification(alert_type: str, description: str, host_id: Optional[UUID] = None):
    if not ALERT_WEBHOOK_URL:
        return  # notifications not configured, silently no-op, this is optional

    try:
        response = requests.post(
            ALERT_WEBHOOK_URL,
            json=_build_payload(alert_type, description, host_id),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code >= 400:
            logger.warning(
                f"Webhook notification failed: {response.status_code} {response.text[:200]}"
            )
    except requests.RequestException as e:
        logger.warning(f"Webhook notification error: {e}")