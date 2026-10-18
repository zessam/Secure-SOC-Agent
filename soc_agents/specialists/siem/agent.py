"""siem specialist agent."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from ..base import build_specialist
from .prompt import ROLE

DESCRIPTION = 'Searches SIEM logs: email, sign-ins, Windows auth, proxy, DNS, firewall, O365.'
TOOLS = [
    ('siem_mcp', ['search_events', 'aggregate_events', 'get_events', 'list_alerts']),
]
TOOL_BUDGET = 12


def build(mode: str = "incident") -> LlmAgent:
    return build_specialist('siem', DESCRIPTION, ROLE, TOOLS, TOOL_BUDGET, mode)
