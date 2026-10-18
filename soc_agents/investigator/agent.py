"""Investigator agent: one verdict and attack story from triage + specialist reports."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from ..common.callbacks import tool_budget
from ..common.models import get_model
from ..common.tools import mcp_tools
from .prompt import INSTRUCTION
from .schema import InvestigationReport


def build_investigator_agent() -> LlmAgent:
    return LlmAgent(
        name="investigator",
        description="Correlates triage and specialist findings into a verdict, timeline and ATT&CK mapping.",
        model=get_model("pro"),
        instruction=INSTRUCTION,
        tools=[  # only to verify cited evidence
            mcp_tools("siem_mcp", ["get_events"]),
            mcp_tools("edr_read_mcp", ["get_events"]),
        ],
        output_schema=InvestigationReport,
        output_key="investigation",
        before_tool_callback=tool_budget(6),
    )
