"""
LLM-assisted alert triage — powered by a locally-run, open-source model
via Ollama. No API key, no per-token cost, and no security log data ever
leaves this machine (a real consideration for a security tool: sending
alert/log content to a third-party API is itself worth scrutinizing).

Given an alert plus the raw log lines that triggered it, asks the local
model for a plain-English summary, a severity rating, and a recommended
next step. Purely advisory — never modifies alerts, takes action, or
blocks/allows anything by itself.

Triage is triggered on demand (POST /alerts/{id}/triage), not automatically
on every alert, so a slow local model can't add latency anywhere else.
"""

import os
import json
import logging

import requests

logger = logging.getLogger("siem-triage")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
REQUEST_TIMEOUT_SECONDS = 60  # local CPU inference is slower than a hosted API — be generous

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
FALLBACK_SEVERITY = "medium"  # used only if the model's JSON is missing/invalid severity

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant. You will be given a security alert "
    "and the raw log lines that triggered it. Produce a concise triage "
    "summary for a human analyst. Base your response ONLY on the data "
    "provided — never invent hosts, IPs, users, or events not present in "
    "the input. Respond with ONLY a JSON object, no markdown fences, no "
    "preamble, in exactly this shape:\n"
    '{"summary": "2-3 plain-English sentences", '
    '"severity": "low" | "medium" | "high" | "critical", '
    '"recommended_action": "one short, concrete next step"}\n'
    "The severity field is REQUIRED and must be exactly one of those four words."
)


def _normalize_severity(value) -> str:
    """
    Small local models occasionally omit the severity field or return
    something outside the expected set, even while returning otherwise
    valid JSON (so this isn't caught as an error). Without this, an alert
    could silently end up with severity=None despite triage "succeeding"
    — which permanently keeps the dashboard's estimated/unconfirmed chip
    styling even though a real triage was run. Normalizing here means
    every successful call produces a real, valid severity.
    """
    if isinstance(value, str) and value.strip().lower() in VALID_SEVERITIES:
        return value.strip().lower()
    logger.warning(f"Model returned missing/invalid severity ({value!r}); defaulting to {FALLBACK_SEVERITY}")
    return FALLBACK_SEVERITY


def _build_user_prompt(alert_type: str, description: str, raw_logs: list[str]) -> str:
    capped_logs = raw_logs[:20]  # keep prompts small and bounded regardless of alert volume
    log_block = "\n".join(f"- {line}" for line in capped_logs) or "(no raw logs available)"
    return (
        f"Alert type: {alert_type}\n"
        f"Alert description: {description}\n\n"
        f"Related raw log lines ({len(capped_logs)} shown):\n{log_block}"
    )


def generate_triage(alert_type: str, description: str, raw_logs: list[str]) -> dict:
    """
    Returns a dict with keys: summary, severity, recommended_action, error.
    On any failure (Ollama unreachable, model not pulled yet, bad response),
    the content fields are None and `error` explains why.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": _build_user_prompt(alert_type, description, raw_logs),
        "stream": False,
        "format": "json",  # asks Ollama to constrain output to valid JSON
    }

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate", json=payload, timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        data = response.json()

        raw_text = data.get("response", "")
        parsed = json.loads(raw_text)

        return {
            "summary": parsed.get("summary"),
            "severity": _normalize_severity(parsed.get("severity")),
            "recommended_action": parsed.get("recommended_action"),
            "error": None,
        }
    except requests.RequestException as e:
        logger.exception("Triage request to Ollama failed")
        return {
            "summary": None,
            "severity": None,
            "recommended_action": None,
            "error": (
                f"Could not reach Ollama at {OLLAMA_URL}: {e}. "
                f"Is the ollama container running, and has the model been pulled?"
            ),
        }
    except (json.JSONDecodeError, KeyError) as e:
        logger.exception("Could not parse Ollama response")
        return {
            "summary": None,
            "severity": None,
            "recommended_action": None,
            "error": f"Could not parse model response: {e}",
        }