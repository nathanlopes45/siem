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
- Respond with EXACTLY ONE Thought/Action pair OR ONE Thought/Final Answer per response. Never write more than one Action, and never write an Action and a Final Answer in the same response — stop immediately after your single Action so you can see its real result before deciding what to do next.
- Only call a tool when it would genuinely change your conclusion. Do not call more than 4 tools total.
- Base every conclusion strictly on the alert data and tool outputs you actually received — never invent hosts, IPs, users, or events.
- Never suggest or imply taking any destructive action (blocking, banning, deleting) — you are investigation-only. recommended_action should describe what a human analyst should look into or do next.
"""

ACTION_NAME_RE = re.compile(r"Action:\s*([A-Za-z_][A-Za-z0-9_]*)")
JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
KEY_VALUE_RE = re.compile(r"(\w+)\s*[=:]\s*['\"]?([^,'\")\n]+)['\"]?")


def _extract_json_object(text: str) -> Optional[dict]:
    """Finds the first {...} blob anywhere in text and parses it. Small
    models sometimes wrap it in extra prose despite instructions not to —
    searching rather than requiring an exact match is more forgiving."""
    if match := JSON_OBJECT_RE.search(text):
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _repair_truncated_json(text: str) -> Optional[dict]:
    """
    Handles a specific, common failure mode: the model's response gets cut
    off mid-object (e.g. a "num_predict" limit hit right after the last
    field, before the closing brace) — the JSON is otherwise complete and
    valid, just missing however many closing brackets/braces it needs.
    Rather than discarding an answer that's 95% there, count what's unclosed
    and append it, then retry parsing.
    """
    start = text.find("{")
    if start == -1:
        return None
    snippet = text[start:].rstrip()
    snippet = re.sub(r",\s*$", "", snippet)  # drop a dangling trailing comma, if any

    open_brackets = snippet.count("[") - snippet.count("]")
    open_braces = snippet.count("{") - snippet.count("}")
    if open_brackets < 0 or open_braces < 0:
        return None  # more closes than opens — not a simple truncation, don't guess

    repaired = snippet + ("]" * open_brackets) + ("}" * open_braces)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        return None


def _extract_key_value_pairs(text: str) -> dict:
    """
    Fallback for when a model writes arguments as key=value or key: value
    pairs instead of valid JSON (e.g. "check_threat_intel(ip=1.2.3.4)" or
    a Final Answer missing its enclosing braces) — salvages what it can
    rather than discarding a mostly-sensible response outright.
    """
    return {k: v.strip() for k, v in KEY_VALUE_RE.findall(text)}


def _parse_action(reply: str) -> Optional[tuple]:
    """
    Returns (tool_name, args_dict) if an Action can be identified, tolerating:
      - the tool name immediately followed by "(args)" on the same line
      - Action Input as valid JSON, key=value pairs, or missing entirely
    Returns None if no "Action:" is present at all.
    """
    name_match = ACTION_NAME_RE.search(reply)
    if not name_match:
        return None
    tool_name = name_match.group(1)

    # Everything after the tool name, through the end of the reply (or the
    # next Thought/Action/Final Answer marker) is fair game for arguments —
    # covers both a same-line "(args)" and a separate "Action Input:" line.
    remainder = reply[name_match.end():]
    cutoff = re.search(r"\n\s*(Thought:|Action:|Final Answer:)", remainder)
    if cutoff:
        remainder = remainder[:cutoff.start()]

    args = _extract_json_object(remainder)
    if args is None:
        args = _repair_truncated_json(remainder)
    if args is None:
        args = _extract_key_value_pairs(remainder)
    return tool_name, args


def _parse_final_answer(reply: str) -> Optional[dict]:
    """Returns the Final Answer dict, tolerating missing braces or minor
    JSON errors by falling back to key/value salvage."""
    if "Final Answer:" not in reply:
        return None
    segment = reply.split("Final Answer:", 1)[1]

    parsed = _extract_json_object(segment)
    if parsed is not None:
        return parsed

    if repaired := _repair_truncated_json(segment):
        return repaired

    # No valid or repairable JSON found — salvage individual fields instead
    # of discarding an otherwise-reasonable answer just because it's missing
    # a brace or a stray quote.
    salvaged = _extract_key_value_pairs(segment)
    if "summary" in salvaged or "severity" in salvaged:
        if "key_evidence" in salvaged:
            salvaged["key_evidence"] = [salvaged["key_evidence"]]
        return salvaged
    return None


def _first_marker(reply: str) -> str:
    """
    Small models sometimes ignore the "one action per turn" instruction and
    write several fabricated Thought/Action/Observation-shaped blocks in a
    SINGLE response, ending with a Final Answer based on tool results it
    never actually received — it's pattern-completing what a full ReAct
    transcript looks like rather than genuinely pausing to wait for a real
    observation. Checking "is there a Final Answer anywhere" before "is
    there an earlier Action" would let that fabricated ending win. Instead,
    whichever marker appears EARLIEST in the raw text is the only one that
    counts; everything the model wrote after that point is discarded, so a
    real tool call and a real observation are always forced in first.
    """
    action_idx = reply.find("Action:")
    final_idx = reply.find("Final Answer:")
    if action_idx == -1 and final_idx == -1:
        return "none"
    if final_idx == -1:
        return "action"
    if action_idx == -1:
        return "final"
    return "action" if action_idx < final_idx else "final"


def _call_ollama_chat(messages: list) -> str:
    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": OLLAMA_AGENT_MODEL,
            "messages": messages,
            "stream": False,
            # Final Answer JSON (summary + severity + recommended_action +
            # key_evidence) can run long enough to hit a default output cap
            # and get truncated mid-object — give it real headroom.
            "options": {"num_predict": 600},
        },
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
        marker = _first_marker(reply)

        if marker == "final":
            if final := _parse_final_answer(reply):
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

        elif marker == "action":
            if action := _parse_action(reply):
                tool_name, tool_input = action
                tool_fn = TOOL_REGISTRY.get(tool_name)
                if tool_fn is None:
                    observation = {"error": f"unknown tool '{tool_name}'"}
                else:
                    try:
                        observation = tool_fn(db, **tool_input)
                        tools_used.append(tool_name)
                    except TypeError as e:
                        # Feeds the error back as an observation so the model can
                        # self-correct with more explicit arguments next turn,
                        # rather than us just discarding the attempt.
                        observation = {"error": f"bad arguments for {tool_name}: {e}"}

                trace.append({"type": "action", "tool": tool_name, "input": tool_input})
                trace.append({"type": "observation", "content": observation})

                # Deliberately do NOT echo the model's full raw reply back —
                # it may contain fabricated later steps (see _first_marker).
                # Only the genuine action + a real observation go back in,
                # which is also what keeps the model anchored to reality
                # rather than continuing its own fabrication next turn.
                messages.append({
                    "role": "assistant",
                    "content": f"Action: {tool_name}\nAction Input: {json.dumps(tool_input)}",
                })
                messages.append({"role": "user", "content": f"Observation: {json.dumps(observation)}"})
                continue

        # Model didn't follow either format, or parsing failed — nudge it
        # once rather than giving up immediately, since small local models
        # sometimes need a reminder to stay in format.
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