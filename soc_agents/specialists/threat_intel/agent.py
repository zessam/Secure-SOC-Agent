"""threat_intel specialist agent."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from ..base import build_specialist
from .prompt import ROLE

DESCRIPTION = 'Checks reputation of IPs, domains, hashes and URLs; links them to campaigns.'
TOOLS = [
    ('ti_mcp', ['lookup_indicators', 'search_campaign']),
    ('edr_read_mcp', ['host_connections']),
]
TOOL_BUDGET = 5


def build(mode: str = "incident") -> LlmAgent:
    return build_specialist('threat_intel', DESCRIPTION, ROLE, TOOLS, TOOL_BUDGET, mode)
