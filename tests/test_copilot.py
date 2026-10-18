"""Copilot wiring (no LLM calls)."""
from __future__ import annotations

import asyncio

from google.adk.tools.agent_tool import AgentTool

from soc_agents.copilot import build_copilot_agent


def test_copilot_has_specialists_and_read_tools_only(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    monkeypatch.setenv("SCENARIO", "A8")
    agent = build_copilot_agent()
    agent_tools = {t.agent.name: t.agent for t in agent.tools if isinstance(t, AgentTool)}
    assert [a.name for a in agent_tools["incident_workflow"].sub_agents] == ["triage", "specialists", "investigator", "response_planner"]
    specialists = [a for n, a in agent_tools.items() if n != "incident_workflow"]
    assert sorted(s.name for s in specialists) == ["edr_specialist", "identity_specialist", "siem_specialist",
                                                   "threat_intel_specialist"]
    # copilot-mode specialists do not depend on triage state and are never skipped
    assert all("{triage}" not in s.instruction and s.before_agent_callback is None for s in specialists)
    assert "2026-10-14T09:00:00Z" in agent.instruction

    async def names():
        out = []
        for ts in [t for t in agent.tools if not isinstance(t, AgentTool)]:
            out += [t.name for t in await ts.get_tools_with_prefix()]
            await ts.close()
        return sorted(out)

    assert asyncio.run(names()) == ["ad_get_host", "ad_get_user", "case_get_case", "case_get_ticket",
                                    "case_search_tickets", "siem_get_alert", "siem_list_alerts"]
