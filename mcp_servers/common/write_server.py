"""Builder for the write-only mock servers (EDR response, AD write, SOAR/network blocking).

Defence in depth, independent of the agents:
1. The server only starts with SOC_IDENTITY=executor (the Executor's non-human identity).
2. Every call must carry an approval id that is approved for exactly this action and target.
3. The kill switch stops every write.
Effects are simulated: each change is appended to runs/system_changes.jsonl.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from soc_platform import approvals, audit, killswitch
from soc_platform.paths import runs_dir

WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)
EXECUTOR_IDENTITY = "executor"


def require_executor_identity(server_name: str) -> None:
    if os.environ.get("SOC_IDENTITY") != EXECUTOR_IDENTITY:
        raise PermissionError(f"{server_name} is write-capable and may only be started by the Executor "
                              f"(SOC_IDENTITY={EXECUTOR_IDENTITY})")


def build_write_server(name: str, system: str, actions: dict[str, str]) -> MCPServer:
    require_executor_identity(name)
    mcp = MCPServer(name, instructions=f"Write-only {system} actions. Executor use only; every call needs an approval id.")

    def make_tool(action: str, description: str):
        def tool(target: str, approval_id: str, incident_id: str) -> dict:
            if killswitch.engaged():
                audit.log(name, "write_refused", incident_id=incident_id, request_id=approval_id,
                          action=action, target=target, reason="kill switch engaged")
                return {"status": "refused", "reason": "kill switch engaged"}
            ok, why = approvals.check_executable(approval_id, action, target)
            if not ok:
                audit.log(name, "write_refused", incident_id=incident_id, request_id=approval_id,
                          action=action, target=target, reason=why)
                return {"status": "refused", "reason": why}
            change = {"change_id": "CHG-" + uuid.uuid4().hex[:8].upper(),
                      "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "system": system,
                      "action": action, "target": target, "approval_id": approval_id, "incident_id": incident_id}
            with (runs_dir() / "system_changes.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(change) + "\n")
            return {"status": "done", **change}

        tool.__name__ = action
        tool.__doc__ = f"{description} (simulated). Requires an approved approval_id for this exact action and target."
        mcp.tool(name=action, annotations=WRITE)(tool)

    for action, description in actions.items():
        make_tool(action, description)
    return mcp


def serve_write(build) -> None:
    build().run("stdio")
