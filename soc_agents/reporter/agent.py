"""Reporter (plain code, no AI): renders the incident ticket from triage, investigation and the reviewed plan.

A template instead of a model call: no extra tokens, no invented facts, and secrets are redacted
before the ticket is stored.
"""
from __future__ import annotations

import re
from typing import AsyncGenerator

from google.adk.agents import BaseAgent
from google.adk.events import Event, EventActions
from google.genai import types

from .redact import redact

PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


def _short(text, n: int = 90) -> str:
    text = str(text or "-").replace("|", "/").replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _hhmm(ts: str | None) -> str:
    m = re.search(r"T(\d{2}:\d{2})", ts or "")
    return m.group(1) if m else (ts or "-")


def _case_id(alert_id: str | None) -> str | None:
    try:
        from mcp_servers.common.store import ScenarioStore  # lab SOAR data
        for case in ScenarioStore().soar_cases:
            if alert_id in case.get("alerts", []):
                return case["case_id"]
    except Exception:  # noqa: BLE001
        pass
    return None


def _status(inv: dict, actions: list[dict]) -> str:
    if inv.get("verdict") == "false_positive":
        return "closed_false_positive"
    if inv.get("verdict") == "benign_true_positive":
        return "closed_benign"
    if inv.get("escalate_to_human") or inv.get("severity") == "critical":
        return "escalated"
    if any(a.get("policy") == "allowed" and a.get("requires_approval") for a in actions):
        return "pending_approval"
    return "monitoring"


def build_report(triage: dict, inv: dict, plan: dict, incident_id: str | None) -> dict:
    """Short one-screen ticket; optional sections appear only when they have content."""
    triage, inv, plan = triage or {}, inv or {}, plan or {}
    actions = plan.get("actions", [])
    scope = inv.get("scope") or {}
    severity = inv.get("severity") or triage.get("severity") or "medium"
    status = _status(inv, actions)
    pending = [a for a in actions if a.get("policy") == "allowed" and a.get("requires_approval")]
    auto = [a for a in actions if a.get("policy") == "allowed" and not a.get("requires_approval")]
    blocked = [a for a in actions if a.get("policy") == "blocked"]

    lines = [f"**{inv.get('verdict', '-')}** · {severity} ({PRIORITY.get(severity, 'P3')}) · "
             f"confidence {inv.get('confidence', '-')} · status {status}",
             "", _short(inv.get("summary") or triage.get("summary"), 400)]
    if inv.get("escalate_to_human"):
        lines += ["", f"**Escalated:** {_short(inv.get('escalate_reason'), 120)}"]

    timeline = inv.get("attack_timeline", [])[:6]
    if timeline:
        lines += ["", "**Timeline (UTC)**"]
        lines += [f"- {_hhmm(s.get('time'))} {_short(s.get('what_happened'), 80)} "
                  f"({(s.get('evidence_event_ids') or ['-'])[0]})" for s in timeline]
    mitre = [m.split()[0] for m in inv.get("mitre_attack", []) if m]
    if mitre:
        lines += ["", f"**ATT&CK:** {', '.join(dict.fromkeys(mitre))}"]
    lines += ["", f"**Compromised:** {', '.join(scope.get('compromised_users', []) + scope.get('compromised_hosts', [])) or '-'}"
              f" · **Clean:** {', '.join(scope.get('checked_and_clean', [])) or '-'}"]
    iocs = [i.get("value") for i in inv.get("indicators", []) if i.get("value")]
    if iocs:
        lines += [f"**IOCs:** {', '.join(_short(v, 20) for v in iocs[:8])}"]

    if pending:
        lines += ["", "**Waiting for approval**", "| ID | Action | Target |", "|---|---|---|"]
        lines += [f"| {a.get('approval_id', '-')} | {a.get('action')} | {_short(a.get('target'), 40)} |" for a in pending]
    if auto:
        lines += ["", "**Auto-approved:** " + ", ".join(f"{a.get('action')} {a.get('target')}" for a in auto)]
    if blocked:
        lines += ["", "**Blocked by policy:** " + "; ".join(
            f"{a.get('action')} {a.get('target')} ({_short(a.get('policy_reason'), 40)})" for a in blocked)]
    if inv.get("suspicious_instructions_seen"):
        lines += ["", "**Prompt injection found:** " + "; ".join(_short(x, 80) for x in inv["suspicious_instructions_seen"])]
    if inv.get("gaps"):
        lines += ["", "**Gaps:** " + "; ".join(_short(g, 80) for g in inv["gaps"][:3])]
    if pending:
        lines += ["", f"Next: `python scripts/approvals.py list --incident {incident_id}`"]

    return {
        "incident_id": incident_id,
        "case_id": _case_id(triage.get("alert_id")),
        "ticket_title": inv.get("title") or _short(triage.get("summary"), 80),
        "priority": PRIORITY.get(severity, "P3"),
        "status": status,
        "report_markdown": "\n".join(lines) + "\n",
    }


def _known_secrets() -> list[str]:
    """Credentials stored in AD descriptions (lab data). In production: a secret scanner / DLP service."""
    try:
        from mcp_servers.common.store import ScenarioStore
        store = ScenarioStore()
        descriptions = [u.get("description") or "" for u in store.ad_users]
        descriptions += [o.get("description") or "" for o in (store.ad_objects.get("overrides") or {}).values()]
        found = []
        for d in descriptions:
            found += re.findall(r"(?i)(?:password|pwd|pass)\s*(?:is|:|=)?\s*([^\s,;]{6,})", d)
        return found
    except Exception:  # noqa: BLE001
        return []


def redact_report(report: dict) -> dict:
    secrets, total = _known_secrets(), 0
    for key, value in list(report.items()):
        if isinstance(value, str):
            report[key], n = redact(value, secrets)
            total += n
    report["redactions"] = total
    return report


class ReportBuilder(BaseAgent):
    """Last workflow step: writes `incident_report` to session state."""

    async def _run_async_impl(self, ctx) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        report = redact_report(build_report(state.get("triage"), state.get("investigation"),
                                            state.get("response_plan"), state.get("incident_id")))
        yield Event(
            invocation_id=ctx.invocation_id, author=self.name, branch=ctx.branch,
            content=types.Content(role="model", parts=[types.Part(text=f"# {report['ticket_title']}\n\n"
                                                                    f"**{report['priority']} | {report['status']}**\n\n"
                                                                    + report["report_markdown"])]),
            actions=EventActions(state_delta={"incident_report": report}),
        )


def build_reporter_agent() -> ReportBuilder:
    return ReportBuilder(name="reporter", description="Renders the incident ticket from the workflow results (no AI).")
