"""Executor: plain code, the ONLY component that holds write access.

It runs approved / auto-approved requests of one incident through the write-only MCP servers,
re-checking the kill switch before every action, and records every result in the queue and audit log.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import Client, StdioServerParameters

from mcp_servers import ad_write_mcp, edr_response_mcp, soar_write_mcp

from . import approvals, audit, killswitch
from .paths import ROOT, approvals_db, runs_dir

SERVERS = {"edr_response_mcp": edr_response_mcp.ACTIONS, "ad_write_mcp": ad_write_mcp.ACTIONS,
           "soar_write_mcp": soar_write_mcp.ACTIONS}
ACTION_SERVER = {action: server for server, actions in SERVERS.items() for action in actions}
MAX_ACTIONS_PER_RUN = 25  # rate limit: a runaway plan cannot fire hundreds of changes


def _params(server: str) -> StdioServerParameters:
    env = {**os.environ, "SOC_IDENTITY": "executor", "PYTHONPATH": str(ROOT),
           "SOC_RUNS_DIR": str(runs_dir()), "SOC_APPROVALS_DB": str(approvals_db())}
    return StdioServerParameters(command=sys.executable, args=["-m", f"mcp_servers.{server}"], env=env, cwd=str(ROOT))


async def execute_incident(incident_id: str) -> list[dict]:
    """Run every approved, not-yet-executed action of an incident. Returns one result per request."""
    if killswitch.engaged():
        audit.log("executor", "execution_refused", incident_id=incident_id, reason="kill switch engaged")
        return [{"status": "refused", "reason": "kill switch engaged"}]

    todo = [r for r in approvals.list_requests(incident_id) if r["status"] in approvals.EXECUTABLE]
    results = []
    if len(todo) > MAX_ACTIONS_PER_RUN:
        audit.log("executor", "rate_limited", incident_id=incident_id, requested=len(todo), limit=MAX_ACTIONS_PER_RUN)
        todo = todo[:MAX_ACTIONS_PER_RUN]

    by_server: dict[str, list[dict]] = {}
    for r in todo:
        server = ACTION_SERVER.get(r["action"])
        if server is None:
            approvals.mark_executed(r["id"], False, {"error": f"no executor mapping for {r['action']}"})
            results.append({"request_id": r["id"], "status": "failed", "reason": "unknown action"})
            continue
        by_server.setdefault(server, []).append(r)

    for server, requests in by_server.items():
        async with Client(_params(server)) as client:
            for r in requests:
                if killswitch.engaged():  # can be pulled mid-run
                    audit.log("executor", "execution_stopped", incident_id=incident_id, reason="kill switch engaged")
                    results.append({"request_id": r["id"], "status": "refused", "reason": "kill switch engaged"})
                    continue
                res = await client.call_tool(r["action"], {"target": r["target"], "approval_id": r["id"],
                                                           "incident_id": incident_id})
                out = json.loads(res.content[0].text) if res.content else {"status": "failed"}
                ok = not res.is_error and out.get("status") == "done"
                approvals.mark_executed(r["id"], ok, out)
                audit.log("executor", "action_executed" if ok else "action_failed", incident_id=incident_id,
                          request_id=r["id"], action=r["action"], target=r["target"], approved_by=r["decided_by"],
                          result=out)
                results.append({"request_id": r["id"], "action": r["action"], "target": r["target"],
                                "status": "executed" if ok else "failed", "detail": out})
    return results


def run(incident_id: str) -> list[dict]:
    return asyncio.run(execute_incident(incident_id))
