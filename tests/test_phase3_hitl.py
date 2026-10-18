"""Phase 3: approval queue, write-only servers, Executor, kill switch, audit."""
from __future__ import annotations

import asyncio
import json
import pathlib
import typing

import pytest
from mcp import Client

from soc_agents.planner.schema import ActionType
from soc_platform import approvals, audit, executor, killswitch

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_RUNS_DIR", str(tmp_path))
    monkeypatch.delenv("SOC_APPROVALS_DB", raising=False)
    monkeypatch.delenv("SOC_KILL_SWITCH", raising=False)
    return tmp_path


def plan(*actions):
    return {"actions": [dict(action=a, target=t, policy=p, requires_approval=ra, reason="r",
                             evidence_event_ids=["A2-EDR-00039"], policy_reason="x") for a, t, p, ra in actions]}


A2_PLAN = plan(("isolate_host", "WS-042", "allowed", True),
               ("block_ip", "203.0.113.201", "allowed", True),
               ("run_av_scan", "WS-033", "allowed", False),
               ("isolate_host", "DC01", "blocked", True))


def by_action(rows):
    return {(r["action"], r["target"]): r for r in rows}


def test_queue_statuses_follow_policy():
    rows = by_action(approvals.submit_plan("INC-1", A2_PLAN))
    assert rows[("isolate_host", "WS-042")]["status"] == "pending"
    assert rows[("run_av_scan", "WS-033")]["status"] == "auto_approved"
    assert rows[("isolate_host", "DC01")]["status"] == "blocked"


def test_only_named_humans_decide_and_blocked_never_approvable():
    rows = by_action(approvals.submit_plan("INC-1", A2_PLAN))
    pending, blocked = rows[("isolate_host", "WS-042")], rows[("isolate_host", "DC01")]
    with pytest.raises(PermissionError):
        approvals.decide(pending["id"], "agent", True)
    with pytest.raises(ValueError):
        approvals.decide(blocked["id"], "z.essam", True)
    with pytest.raises(ValueError):
        approvals.decide(pending["id"], "z.essam", False)  # rejection needs a reason
    assert approvals.decide(pending["id"], "z.essam", True)["status"] == "approved"


def test_every_plannable_action_has_an_executor_mapping():
    assert set(typing.get_args(ActionType)) == set(executor.ACTION_SERVER)


def test_write_servers_refuse_to_start_without_executor_identity(monkeypatch):
    from mcp_servers import ad_write_mcp, edr_response_mcp, soar_write_mcp
    monkeypatch.delenv("SOC_IDENTITY", raising=False)
    for mod in (edr_response_mcp, ad_write_mcp, soar_write_mcp):
        with pytest.raises(PermissionError):
            mod.build_server()


def test_no_agent_is_wired_to_a_write_server():
    src = "\n".join(p.read_text() for p in (ROOT / "soc_agents").rglob("*.py"))
    for server in ("edr_response_mcp", "ad_write_mcp", "soar_write_mcp"):
        assert server not in src


def test_write_server_rechecks_approval(monkeypatch):
    from mcp_servers import edr_response_mcp
    monkeypatch.setenv("SOC_IDENTITY", "executor")
    rows = by_action(approvals.submit_plan("INC-1", A2_PLAN))
    pending = rows[("isolate_host", "WS-042")]

    async def call(target, approval_id):
        async with Client(edr_response_mcp.build_server()) as c:
            r = await c.call_tool("isolate_host", {"target": target, "approval_id": approval_id, "incident_id": "INC-1"})
            return json.loads(r.content[0].text)

    assert asyncio.run(call("WS-042", pending["id"]))["status"] == "refused"  # still pending
    approvals.decide(pending["id"], "z.essam", True)
    assert asyncio.run(call("WS-099", pending["id"]))["status"] == "refused"  # wrong target
    assert asyncio.run(call("WS-042", "APR-FAKE0000"))["status"] == "refused"  # forged id
    assert asyncio.run(call("WS-042", pending["id"]))["status"] == "done"


def test_executor_runs_only_approved_and_logs_everything(isolated_runs):
    rows = by_action(approvals.submit_plan("INC-A2", A2_PLAN))
    approvals.decide(rows[("isolate_host", "WS-042")]["id"], "z.essam", True, "confirmed C2")
    approvals.decide(rows[("block_ip", "203.0.113.201")]["id"], "z.essam", False, "shared hosting, block domain instead")

    results = executor.run("INC-A2")
    executed = {(r["action"], r["target"]) for r in results if r["status"] == "executed"}
    assert executed == {("isolate_host", "WS-042"), ("run_av_scan", "WS-033")}

    final = by_action(approvals.list_requests("INC-A2"))
    assert final[("block_ip", "203.0.113.201")]["status"] == "rejected"
    assert final[("isolate_host", "DC01")]["status"] == "blocked"
    changes = (isolated_runs / "system_changes.jsonl").read_text().splitlines()
    assert len(changes) == 2
    events = [e["event"] for e in audit.read("INC-A2")]
    assert events.count("action_executed") == 2 and "request_rejected" in events

    assert executor.run("INC-A2") == []  # nothing runs twice


def test_kill_switch_stops_execution(isolated_runs):
    rows = by_action(approvals.submit_plan("INC-K", A2_PLAN))
    approvals.decide(rows[("isolate_host", "WS-042")]["id"], "z.essam", True)
    killswitch.engage("soc-lead", "testing")
    assert executor.run("INC-K")[0]["status"] == "refused"
    assert not (isolated_runs / "system_changes.jsonl").exists()
    killswitch.release("soc-lead")
    assert {r["status"] for r in executor.run("INC-K")} == {"executed"}
