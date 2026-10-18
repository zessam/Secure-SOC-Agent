"""identity specialist agent."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from ..base import build_specialist
from .prompt import ROLE

DESCRIPTION = 'Checks accounts: AD attributes, group membership, Entra ID sign-ins, MFA, directory changes.'
TOOLS = [
    ('ad_mcp', ['get_user', 'get_group', 'search_users', 'get_host', 'signin_history', 'directory_changes']),
]
TOOL_BUDGET = 10


def build() -> LlmAgent:
    return build_specialist('identity', DESCRIPTION, ROLE, TOOLS, TOOL_BUDGET)
