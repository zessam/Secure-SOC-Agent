"""Connects agents to the mock MCP servers, each agent getting only the tools it needs."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams
from mcp import StdioServerParameters

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def mcp_tools(server: str, allowed: list[str]) -> McpToolset:
    """Launch mcp_servers.<server> for the current SCENARIO and expose only `allowed` tools."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", f"mcp_servers.{server}"],
        env={**os.environ, "SCENARIO": os.environ.get("SCENARIO", "A2"), "PYTHONPATH": str(PROJECT_ROOT)},
        cwd=str(PROJECT_ROOT),
    )
    return McpToolset(
        connection_params=StdioConnectionParams(server_params=params, timeout=30),
        tool_filter=allowed,
        tool_name_prefix=server.removesuffix("_mcp").replace("_read", ""),
    )
