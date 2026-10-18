"""Tool budget guard."""
from __future__ import annotations

from types import SimpleNamespace

from soc_agents.common.callbacks import tool_budget


def _ctx():
    return SimpleNamespace(state={}, invocation_id="inv1", agent_name="edr_specialist")


def test_budget_blocks_investigation_tools_but_never_the_final_answer():
    guard, ctx = tool_budget(2), _ctx()
    search = SimpleNamespace(name="edr_search_host_events")
    final = SimpleNamespace(name="set_model_response")
    assert guard(search, {}, ctx) is None
    assert guard(search, {}, ctx) is None
    blocked = guard(search, {}, ctx)
    assert "set_model_response" in blocked["error"]
    assert guard(final, {}, ctx) is None  # can always submit the report


def test_budget_is_per_run():
    guard, ctx = tool_budget(1), _ctx()
    tool = SimpleNamespace(name="siem_search_events")
    assert guard(tool, {}, ctx) is None
    assert guard(tool, {}, ctx) is not None
    ctx.invocation_id = "inv2"  # a new alert / run gets a fresh budget
    assert guard(tool, {}, ctx) is None
