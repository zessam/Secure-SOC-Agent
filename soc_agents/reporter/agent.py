"""Reporter: writes the incident ticket from triage, investigation and the reviewed response plan."""
from __future__ import annotations

import re

from google.adk.agents import LlmAgent

from ..common.callbacks import tool_budget
from ..common.models import get_model
from ..common.tools import mcp_tools
from .prompt import INSTRUCTION
from .redact import redact
from .schema import IncidentReport


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


def redact_report(callback_context):
    """after_agent_callback: redact secrets from every text field of the stored report."""
    report = callback_context.state.get("incident_report")
    if not isinstance(report, dict):
        return None
    secrets, total = _known_secrets(), 0
    for key, value in report.items():
        if isinstance(value, str):
            report[key], n = redact(value, secrets)
            total += n
        elif isinstance(value, list):
            cleaned = []
            for item in value:
                if isinstance(item, str):
                    item, n = redact(item, secrets)
                    total += n
                cleaned.append(item)
            report[key] = cleaned
    report["redactions"] = total
    callback_context.state["incident_report"] = report
    return None


def build_reporter_agent() -> LlmAgent:
    return LlmAgent(
        name="reporter",
        description="Writes the incident ticket (summary, timeline, ATT&CK, IOCs, proposed actions).",
        model=get_model("flash"),
        instruction=INSTRUCTION,
        tools=[mcp_tools("case_mcp", ["get_case"])],
        output_schema=IncidentReport,
        output_key="incident_report",
        before_tool_callback=tool_budget(2),
        after_agent_callback=redact_report,
    )
