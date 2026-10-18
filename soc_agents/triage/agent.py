"""Triage agent: first look at an alert. Read-only; decides severity, scope and what to investigate."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from ..common.callbacks import tool_budget
from ..common.models import get_model
from .prompt import INSTRUCTION
from .schema import TriageResult
from ..common.tools import mcp_tools


def build_triage_agent() -> LlmAgent:
    return LlmAgent(
        name="triage",
        description="First look at a SOC alert: severity, entities, time window, what to investigate.",
        model=get_model("pro"),
        instruction=INSTRUCTION,
        tools=[
            mcp_tools("siem_mcp", ["get_alert", "get_events", "list_alerts"]),
            mcp_tools("edr_read_mcp", ["get_events"]),
            mcp_tools("ad_mcp", ["get_user", "get_host"]),
            mcp_tools("case_mcp", ["get_case", "search_changes"]),
        ],
        include_contents="none",  # inputs come via {state} in the instruction, not chat history
        output_schema=TriageResult,
        output_key="triage",
        before_tool_callback=tool_budget(8),
    )
