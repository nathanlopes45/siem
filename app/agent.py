"""
Agentic alert investigation — a hand-rolled ReAct (Reasoning + Acting) loop.

Unlike triage.py (a single prompt -> single JSON answer), this lets the
model decide what additional context it needs, call read-only tools to
fetch it, observe the results, and decide again — repeating until it has
enough information to conclude, or it hits a hard iteration cap.

Design principles, stated explicitly because they matter for a security
tool specifically:
  - Every tool is READ-ONLY. The agent can look, but it can never take
    action (block an IP, kill a process, modify data) on its own. Giving
    an LLM agent write/destructive capability in a security context is a
    real risk surface; this agent is investigation-only by design.
  - Bounded iterations (MAX_ITERATIONS) — no possibility of a runaway
    loop burning time or tokens indefinitely.
  - Full trace persisted (see models.AgentInvestigation) — every thought,
    tool call, and observation is stored, not just the final answer. An
    analyst (or you, in an interview) can see exactly how the agent got
    to its conclusion, not just trust it blindly.
  - Falls back to the existing single-shot triage (triage.generate_triage)
    if the agent can't produce a valid Final Answer within the iteration
    cap — small local models aren't always reliable at strict output
    formats, so this needs a safety net rather than failing outright.
"""

import os
import re
import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

import requests
from sqlalchemy.orm import Session

from . import models
from .triage import generate_triage, _normalize_severity

logger = logging.getLogger("siem-agent")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
# Agent reasoning is a harder task than single-shot classification, so it's
# configurable separately from the triage model — bump this to a larger
# local model (e.g. llama3.2:3b) if the smaller default is unreliable at
# following the Thought/Action format.
OLLAMA_AGENT_MODEL = os.getenv("OLLAMA_AGENT_MODEL", os.getenv("OLLAMA_MODEL", "llama3.2:1b"))
REQUEST_TIMEOUT_SECONDS = 60
MAX_ITERATIONS = 5


# ---------------------------------------------------------------------------
# Tools — every one is read-only. Each takes (db, **kwargs) and returns a
# JSON-serializable dict. Add new tools here + in TOOL_REGISTRY + the
# system prompt's tool list to extend the agent's capabilities.
# ---------------------------------------------------------------------------

def tool_get_recent_logs(db: Session, host_id: str, event_type: Optional[str] = None, limit: int = 15) -> dict:
    query = db.query(models.RawLog).filter(models.RawLog.host_id == host_id)
    if event_type:
        query = query.filter(models.RawLog.event_type == event_type)
    logs = query.order_by(models.RawLog.received_at.desc()).limit(limit).all()
    return {"count": len(logs), "logs": [l.raw_log for l in logs]}


def tool_check_threat_intel(db: Session, ip: str) -> dict:
    from .detections import THREAT_INTEL_IPS
    return {"ip": ip, "is_known_malicious": ip in THREAT_INTEL_IPS}


def tool_check_cross_host_activity(db: Session, ip: str, window_minutes: int = 60) -> dict:
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    rows = (
        db.query(models.RawLog.host_id)
        .filter(models.RawLog.attacker_ip == ip, models.RawLog.received_at >= since)
        .distinct()
        .all()
    )
    host_ids = [str(r[0]) for r in rows]
    return {"ip": ip, "distinct_hosts_hit": len(host_ids), "host_ids": host_ids, "window_minutes": window_minutes}


def tool_get_host_info(db: Session, host_id: str) -> dict:
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        return {"error": "host not found"}
    return {"hostname": host.hostname, "ip_address": host.ip_address, "os_type": host.os_type}


TOOL_REGISTRY = {
    "get_recent_logs": tool_get_recent_logs,
    "check_threat_intel": tool_check_threat_intel,
    "check_cross_host_activity": tool_check_cross_host_activity,
    "get_host_info": tool_get_host_info,
}

SYSTEM_PROMPT = """You are a SOC analyst agent investigating a security alert. You have read-only tools to gather more context before concluding — you cannot take any action, only look.

Available tools:
- get_recent_logs(host_id, event_type, limit): recent raw log lines for a host, optionally filtered by event_type (e.g. failed_password, http_4xx)
- check_threat_intel(ip): whether an IP is on the known-malicious list
- check_cross_host_activity(ip): how many distinct hosts an IP has hit recently
- get_host_info(host_id): hostname/os_type/ip for a host

Respond using EXACTLY one of these two formats, nothing else, no other text:

Thought: <your reasoning about what to do next>
Action: <tool name>
Action Input: <a single-line JSON object of arguments>

OR, when you have enough information to conclude:

Thought: <your final reasoning>
Final Answer: <a single-line JSON object with keys: summary (2-3 sentences), severity (one of: low, medium, high, critical), recommended_action (one short concrete step), key_evidence (a list of short strings)>

Rules:
- Only call a tool when it would genuinely change your conclusion. Do not call more than 4 tools total.
- Base every conclusion strictly on the alert data and tool outputs you actually received — never invent hosts, IPs, users, or events.
- Never suggest or imply taking any destructive action (blocking, banning, deleting) — you are investigation-only. recommended_action should describe what a human analyst should look into or do next.
"""

ACTION_RE = re.compile(r"Action:\s*(\w+)\s*\nAction Input:\s*(\{.*\})", re.DOTALL)
FINAL_RE = re.compile(r"Final Answer:\s*(\{.*\})", re.DOTALL)


def _call_ollama_chat(messages: list) -> str:
    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={"model": OLLAMA_AGENT_MODEL, "messages": messages, "stream": False},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["message"]["content"]


def run_agent_investigation(db: Session, alert: models.Alert) -> dict:
    """
    Runs the ReAct loop for a single alert. Returns a dict with:
    summary, severity, recommended_action, key_evidence, trace (list of
    step dicts), tools_used (list of tool names), iterations (int),
    fell_back (bool — True if we had to use the simple triage fallback).
    """
    trace = []
    tools_used = []

    initial_context = (
        f"Alert type: {alert.alert_type}\n"
        f"Description: {alert.description}\n"
        f"Host ID: {alert.host_id if alert.host_id else 'none (fleet-wide finding)'}\n\n"
        f"Investigate this alert and provide your Final Answer."
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": initial_context},
    ]
    trace.append({"type": "context", "content": initial_context})

    for iteration in range(1, MAX_ITERATIONS + 1):
        try:
            reply = _call_ollama_chat(messages)
        except requests.RequestException as e:
            logger.exception("Agent: Ollama call failed")
            return _fallback(db, alert, trace, tools_used, iteration, reason=f"Ollama unreachable: {e}")

        trace.append({"type": "model", "content": reply})

        if final_match := FINAL_RE.search(reply):
            try:
                final = json.loads(final_match.group(1))
                return {
                    "summary": final.get("summary"),
                    "severity": _normalize_severity(final.get("severity")),
                    "recommended_action": final.get("recommended_action"),
                    "key_evidence": final.get("key_evidence", []),
                    "trace": trace,
                    "tools_used": tools_used,
                    "iterations": iteration,
                    "fell_back": False,
                }
            except json.JSONDecodeError:
                pass  # fall through to nudge the model below

        if action_match := ACTION_RE.search(reply):
            tool_name = action_match.group(1)
            try:
                tool_input = json.loads(action_match.group(2))
            except json.JSONDecodeError:
                tool_input = {}

            tool_fn = TOOL_REGISTRY.get(tool_name)
            if tool_fn is None:
                observation = {"error": f"unknown tool '{tool_name}'"}
            else:
                try:
                    observation = tool_fn(db, **tool_input)
                    tools_used.append(tool_name)
                except TypeError as e:
                    observation = {"error": f"bad arguments for {tool_name}: {e}"}

            trace.append({"type": "action", "tool": tool_name, "input": tool_input})
            trace.append({"type": "observation", "content": observation})

            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": f"Observation: {json.dumps(observation)}"})
            continue

        # Model didn't follow either format — nudge it once rather than
        # giving up immediately, since small local models sometimes need
        # a reminder to stay in format.
        messages.append({"role": "assistant", "content": reply})
        messages.append({
            "role": "user",
            "content": "Please respond using exactly the Thought/Action/Action Input "
                       "or Thought/Final Answer format described above.",
        })

    return _fallback(db, alert, trace, tools_used, MAX_ITERATIONS,
                      reason=f"No valid Final Answer within {MAX_ITERATIONS} iterations")


def _fallback(db: Session, alert: models.Alert, trace: list, tools_used: list, iterations: int, reason: str) -> dict:
    """Safety net: if the agent loop can't conclude, fall back to the
    simpler, more reliable single-shot triage rather than returning nothing."""
    trace.append({"type": "fallback", "content": reason})
    logger.warning(f"Agent investigation fell back to simple triage: {reason}")

    logs_query = db.query(models.RawLog.raw_log)
    if alert.host_id:
        logs_query = logs_query.filter(models.RawLog.host_id == alert.host_id)
    related_logs = [r[0] for r in logs_query.order_by(models.RawLog.received_at.desc()).limit(20).all()]

    result = generate_triage(alert.alert_type, alert.description, related_logs)
    return {
        "summary": result["summary"],
        "severity": result["severity"],
        "recommended_action": result["recommended_action"],
        "key_evidence": [],
        "trace": trace,
        "tools_used": tools_used,
        "iterations": iterations,
        "fell_back": True,
    }