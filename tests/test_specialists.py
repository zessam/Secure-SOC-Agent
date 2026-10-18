"""Specialist wiring (no LLM calls): least-privilege tools, parallel layout, skip logic."""
from __future__ import annotations

import asyncio

from soc_agents.specialists import build_specialists
from soc_agents.specialists.base import skip_unless_requested as _skip_unless_requested
from soc_agents.specialists.schema import SpecialistFindings
from soc_agents.workflow import build_incident_workflow


class _Ctx:
    def __init__(self, state):
        self.state = state


def test_specialist_tools_are_least_privilege(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    monkeypatch.setenv("SCENARIO", "A2")
    par = build_specialists()

    async def names():
        out = {}
        for agent in par.sub_agents:
            out[agent.name] = []
            for ts in agent.tools:
                out[agent.name] += [t.name for t in await ts.get_tools_with_prefix()]
                await ts.close()
        return out

    tools = asyncio.run(names())
    assert set(tools) == {"siem_specialist", "edr_specialist", "identity_specialist", "threat_intel_specialist"}
    assert all(t.startswith("siem_") for t in tools["siem_specialist"])
    assert all(t.startswith("edr_") for t in tools["edr_specialist"])
    assert all(t.startswith("ad_") for t in tools["identity_specialist"])
    assert sorted(tools["threat_intel_specialist"]) == ["edr_host_connections", "ti_lookup_indicators",
                                                        "ti_search_campaign"]


def test_workflow_order(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    wf = build_incident_workflow()
    assert [a.name for a in wf.sub_agents] == ["triage", "specialists", "investigator"]


def test_specialist_skipped_when_not_requested():
    state = {"triage": {"specialists_needed": ["edr", "threat_intel"]}}
    content = _skip_unless_requested("identity")(_Ctx(state))
    # the skip message must itself be a valid specialist report (ADK validates it against output_schema)
    report = SpecialistFindings.model_validate_json(content.parts[0].text)
    assert report.specialist == "identity" and report.summary.startswith("Skipped")
    assert _skip_unless_requested("edr")(_Ctx(state)) is None
