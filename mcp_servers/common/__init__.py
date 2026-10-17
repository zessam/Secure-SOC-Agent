from __future__ import annotations

import argparse
from typing import Callable

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .store import ScenarioStore

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


def serve(build: Callable[[ScenarioStore], MCPServer]) -> None:
    """CLI entry point shared by all servers: SCENARIO=A2 python -m mcp_servers.siem_mcp [--transport ...]."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", help="Scenario id, e.g. A2 (default: $SCENARIO)")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"])
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = build(ScenarioStore(args.scenario))
    if args.transport == "stdio":
        server.run("stdio")
    else:
        server.run("streamable-http", port=args.port)
