"""Reporter: wiring and secret redaction (no LLM calls)."""
from __future__ import annotations

from types import SimpleNamespace

from soc_agents.reporter import build_reporter_agent
from soc_agents.reporter.agent import redact_report
from soc_agents.reporter.redact import redact


def test_redacts_password_patterns_and_known_secrets():
    text, n = redact("svc pwd: Autumn#2026! and later Autumn#2026! again; api_key=abcd1234efgh", ["Autumn#2026!"])
    assert "Autumn#2026!" not in text and "abcd1234efgh" not in text
    assert n >= 3


def test_report_redacted_before_storing(monkeypatch):
    monkeypatch.setenv("SCENARIO", "S4")
    state = {"incident_report": {
        "ticket_title": "Secret in AD", "report_markdown": "The description contains Autumn#2026! for svc-legacyapp",
        "analyst_next_steps": ["Rotate Autumn#2026!"], "priority": "P2"}}
    redact_report(SimpleNamespace(state=state))
    report = state["incident_report"]
    assert "Autumn#2026!" not in report["report_markdown"]
    assert "Autumn#2026!" not in report["analyst_next_steps"][0]
    assert report["redactions"] == 2


def test_reporter_wiring(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    agent = build_reporter_agent()
    assert agent.output_key == "incident_report" and agent.after_agent_callback is not None
    for key in ("{triage}", "{investigation}", "{response_plan}"):
        assert key in agent.instruction
