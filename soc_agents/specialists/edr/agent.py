"""edr specialist agent."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from ..base import build_specialist
from .prompt import ROLE

DESCRIPTION = 'Investigates endpoints: process trees, network connections, files, registry, detections.'
TOOLS = [
    ('edr_read_mcp', ['get_process_tree', 'host_connections', 'search_host_events', 'get_detections', 'find_indicator', 'aggregate_host_events', 'get_events']),
]
TOOL_BUDGET = 12


def build(mode: str = "incident") -> LlmAgent:
    return build_specialist('edr', DESCRIPTION, ROLE, TOOLS, TOOL_BUDGET, mode)
