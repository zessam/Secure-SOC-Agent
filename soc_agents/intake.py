"""Intake (plain code, no AI): first step of every chat message in the incident workflow.

- A message with an alert id (ALR-...) starts the investigation, once per alert per session
  (say "rerun ALR-..." to investigate it again).
- Approval commands are handled here in code; they never start the AI agents:
    status | approve all as <name> | approve APR-XXXXXXXX as <name>
    reject APR-XXXXXXXX as <name> because <reason> | execute
- Anything else gets a short help message instead of an expensive pipeline run.
"""
from __future__ import annotations

import re

from google.genai import types

from soc_platform import approvals, executor

ALERT_RE = re.compile(r"\bALR-[A-Z0-9]+-\d{3}\b", re.I)
APPROVE_ALL_RE = re.compile(r"^\s*approve\s+all\b(?:\s+as\s+(?P<name>[\w.\-@]+))?", re.I)
APPROVE_RE = re.compile(r"^\s*approve\s+(?P<id>APR-[0-9A-F]{8})\b(?:\s+as\s+(?P<name>[\w.\-@]+))?", re.I)
REJECT_RE = re.compile(r"^\s*reject\s+(?P<id>APR-[0-9A-F]{8})\b(?:\s+as\s+(?P<name>[\w.\-@]+))?"
                       r"(?:\s+(?:because|reason:?)\s+(?P<reason>.+))?", re.I | re.S)
HELP = """I handle **one SIEM alert per message**. Examples:
- `New SIEM alert ALR-A2-001. Triage it.` - investigate an alert
- `status` - show the approval queue for the current incident
- `approve all as <your name>` / `approve APR-XXXXXXXX as <your name>`
- `reject APR-XXXXXXXX as <your name> because <reason>`
- `execute` - run the approved actions"""

ICON = {"pending": "⏳", "approved": "✅", "auto_approved": "🤖", "rejected": "❌", "blocked": "⛔",
        "executed": "✔️", "failed": "💥", "superseded": "↩️"}


def _scenario_exists(scenario: str) -> bool:
    import json
    from mcp_servers.common.store import DEFAULT_DATA_DIR
    catalog = json.loads((DEFAULT_DATA_DIR / "scenarios" / "catalog.json").read_text(encoding="utf-8"))
    return any(e["id"].upper() == scenario.upper() for e in catalog["scenarios"])


def _reply(text: str) -> types.Content:
    return types.Content(role="model", parts=[types.Part(text=text)])


def _queue_table(incident_id: str) -> str:
    rows = approvals.list_requests(incident_id)
    if not rows:
        return f"No actions queued for `{incident_id}`."
    lines = [f"**Incident `{incident_id}`**", "", "| | ID | Status | Action | Target |", "|---|---|---|---|---|"]
    for r in rows:
        target = r["target"] if len(r["target"]) <= 45 else r["target"][:44] + "…"
        lines.append(f"| {ICON.get(r['status'], '')} | {r['id']} | {r['status']} | {r['action']} | {target} |")
    return "\n".join(lines)


def _need_name(cmd: str) -> types.Content:
    return _reply(f"Approvals must name a human. Try: `{cmd} as <your name>`")


async def intake_router(callback_context):
    """before_agent_callback on the workflow: return a reply to skip the AI pipeline, or None to run it."""
    content = callback_context.user_content
    text = " ".join(p.text for p in (content.parts if content else []) or [] if p.text).strip()
    state = callback_context.state
    incident_id = state.get("incident_id")

    if m := APPROVE_ALL_RE.match(text):
        if not incident_id:
            return _reply("No incident in this session yet. Send an alert first.")
        if not m["name"]:
            return _need_name("approve all")
        for r in approvals.list_requests(incident_id, "pending"):
            approvals.decide(r["id"], m["name"], True, "approved in chat")
        return _reply(_queue_table(incident_id) + "\n\nSay `execute` to run the approved actions.")

    if m := APPROVE_RE.match(text):
        if not m["name"]:
            return _need_name(f"approve {m['id'].upper()}")
        try:
            approvals.decide(m["id"].upper(), m["name"], True, "approved in chat")
        except (KeyError, ValueError, PermissionError) as e:
            return _reply(f"Not approved: {e}")
        return _reply(_queue_table(incident_id or approvals.get(m["id"].upper())["incident_id"]))

    if m := REJECT_RE.match(text):
        if not m["name"] or not m["reason"]:
            return _reply(f"Try: `reject {m['id'].upper()} as <your name> because <reason>`")
        try:
            approvals.decide(m["id"].upper(), m["name"], False, m["reason"].strip())
        except (KeyError, ValueError, PermissionError) as e:
            return _reply(f"Not rejected: {e}")
        return _reply(_queue_table(incident_id or approvals.get(m["id"].upper())["incident_id"]))

    if re.match(r"^\s*execute\b", text, re.I):
        if not incident_id:
            return _reply("No incident in this session yet.")
        results = await executor.execute_incident(incident_id)
        done = [r for r in results if r.get("status") == "executed"]
        msg = f"Executed {len(done)} action(s)." if results else "Nothing approved to execute."
        if results and results[0].get("reason") == "kill switch engaged":
            msg = "⛔ Kill switch is engaged: nothing was executed."
        return _reply(msg + "\n\n" + _queue_table(incident_id))

    if re.match(r"^\s*(status|queue|list)\b", text, re.I):
        return _reply(_queue_table(incident_id) if incident_id else "No incident in this session yet.")

    if m := ALERT_RE.search(text):
        alert_id = m.group(0).upper()
        handled = state.get("handled_alerts") or {}
        if alert_id in handled and not re.search(r"\b(rerun|re-run|again)\b", text, re.I):
            return _reply(f"`{alert_id}` was already investigated in this session (incident `{handled[alert_id]}`).\n\n"
                          f"{_queue_table(handled[alert_id])}\n\nSay `rerun {alert_id}` to investigate it again.")
        scenario = alert_id.split("-")[1]
        if not _scenario_exists(scenario):
            return _reply(f"Unknown alert `{alert_id}`: no scenario `{scenario}` in the lab data.")
        state["current_alert"] = alert_id
        state["scenario"] = scenario  # every tool call of this run is scoped to it
        return None  # run the AI pipeline

    if re.match(r"^\s*(approve|reject|yes|ok|go)\b", text, re.I):
        return _reply("To approve, name the action and yourself, e.g. `approve all as <your name>`.\n\n" + HELP)
    return _reply(HELP)
