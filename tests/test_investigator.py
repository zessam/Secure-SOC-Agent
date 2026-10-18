"""Investigator wiring (no LLM calls)."""
from __future__ import annotations

import asyncio

from soc_agents.investigator import build_investigator_agent
from soc_agents.investigator.schema import InvestigationReport


def test_investigator_only_verifies_evidence(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    monkeypatch.setenv("SCENARIO", "A2")
    agent = build_investigator_agent()

    async def names():
        out = []
        for ts in agent.tools:
            out += [t.name for t in await ts.get_tools_with_prefix()]
            await ts.close()
        return sorted(out)

    assert asyncio.run(names()) == ["edr_get_events", "siem_get_events"]
    assert agent.output_key == "investigation"
    for key in ("{triage}", "{edr_findings?}", "{siem_findings?}", "{identity_findings?}", "{threat_intel_findings?}"):
        assert key in agent.instruction


def test_report_accepts_json_string_fields():
    r = InvestigationReport.model_validate({
        "title": "t", "verdict": "true_positive", "confidence": "high", "severity": "high",
        "executive_summary": "s", "root_cause": "phish",
        "attack_timeline": '[{"time": "2026-10-13T10:16:05Z", "what_happened": "ps", "evidence_event_ids": ["A2-EDR-00035"]}]',
        "mitre_attack": [{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
        "scope": '{"compromised_users": ["s.khan"], "compromised_hosts": ["WS-042"]}',
        "indicators": [], "what_needs_containing": ["WS-042"], "escalate_to_human": False,
    })
    assert r.scope.compromised_hosts == ["WS-042"]
    assert r.attack_timeline[0].mitre_technique is None
