from __future__ import annotations

import argparse
import os
import functools
import inspect
import json
from typing import Callable

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .store import MultiStore, ScenarioStore, active_scenario

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


def compact(result) -> str:
    """Compact JSON without nulls: ~40% fewer tokens than the SDK's pretty-printed default."""
    def strip(v):
        if isinstance(v, dict):
            return {k: strip(x) for k, x in v.items() if x is not None and x != [] and x != {}}
        if isinstance(v, list):
            return [strip(x) for x in v]
        return v
    return json.dumps(strip(result), separators=(",", ":"), ensure_ascii=False, default=str)


def read_tool(mcp: MCPServer):
    """Register a read-only tool: result sent as compact JSON; optional `scenario` scopes the call.

    `scenario` is set by the platform (agent-side callback from the alert id), not by the model.
    """
    def register(fn):
        sig = inspect.signature(fn)
        scenario_param = inspect.Parameter("scenario", inspect.Parameter.KEYWORD_ONLY, default="", annotation=str)

        @functools.wraps(fn)
        def wrapper(*args, scenario: str = "", **kwargs):
            token = active_scenario.set(scenario.upper()) if scenario else None
            try:
                return compact(fn(*args, **kwargs))
            finally:
                if token is not None:
                    active_scenario.reset(token)

        wrapper.__signature__ = sig.replace(parameters=[*sig.parameters.values(), scenario_param],
                                            return_annotation=str)
        wrapper.__annotations__ = {**fn.__annotations__, "scenario": str, "return": str}
        mcp.tool(annotations=READ_ONLY)(wrapper)
        return fn
    return register


def serve(build: Callable[[ScenarioStore], MCPServer]) -> None:
    """CLI entry point shared by all servers: SCENARIO=A2 python -m mcp_servers.siem_mcp [--transport ...]."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", help="Scenario id, e.g. A2 (default: $SCENARIO)")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"])
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    scenario = (args.scenario or os.environ.get("SCENARIO") or "").upper()
    # ALL = every scenario merged into one dataset; otherwise one server serves any scenario per call.
    store = ScenarioStore("ALL") if scenario == "ALL" else MultiStore(default=scenario if scenario != "AUTO" else None)
    server = build(store)
    if args.transport == "stdio":
        server.run("stdio")
    else:
        server.run("streamable-http", port=args.port)
