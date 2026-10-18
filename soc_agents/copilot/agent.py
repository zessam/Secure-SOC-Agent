"""Analyst Copilot: the analyst's chat entry point. Answers questions with the specialists and runs
the full incident workflow (Triage -> specialists -> Investigator) when the analyst reports an alert."""
from __future__ import annotations

import os

from google.adk.agents import LlmAgent
from google.adk.tools.agent_tool import AgentTool

from ..common.callbacks import tool_budget
from ..common.models import get_model
from ..common.tools import mcp_tools
from ..specialists import edr, identity, siem, threat_intel
from ..workflow import build_incident_workflow
from .prompt import INSTRUCTION

LAB_NOW = "2026-10-14T09:00:00Z"  # the synthetic data's "current time"


def build_copilot_agent() -> LlmAgent:
    specialists = [m.build(mode="copilot") for m in (siem, edr, identity, threat_intel)]
    return LlmAgent(
        name="analyst_copilot",
        description="Answers analyst questions about hosts, users, alerts, cases and IOCs (read-only).",
        model=get_model("pro"),
        instruction=INSTRUCTION.replace("{now}", os.environ.get("SOC_NOW", LAB_NOW)),
        tools=[
            AgentTool(agent=build_incident_workflow()),
            *[AgentTool(agent=s) for s in specialists],
            mcp_tools("siem_mcp", ["get_alert", "list_alerts"]),
            mcp_tools("ad_mcp", ["get_user", "get_host"]),
            mcp_tools("case_mcp", ["get_case", "get_ticket", "search_tickets"]),
        ],
        before_tool_callback=tool_budget(15),
    )
