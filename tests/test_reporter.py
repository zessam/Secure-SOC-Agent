"""Reporter (plain code): ticket rendering and secret redaction."""
from __future__ import annotations

from soc_agents.reporter import build_reporter_agent
from soc_agents.reporter.agent import build_report, redact_report
from soc_agents.reporter.redact import redact

INV = {"title": "Macro malware on WS-042", "verdict": "true_positive", "severity": "high", "confidence": "high",
       "summary": "s.khan opened a malicious invoice. Malware beaconed to C2.",
       "attack_timeline": [{"time": "2026-10-13T10:16:05Z", "what_happened": "Encoded PowerShell",
                            "evidence_event_ids": ["A2-EDR-00035"], "mitre_technique": "T1059.001"}],
       "mitre_attack": ["T1059.001 PowerShell (Execution)"],
       "scope": {"compromised_hosts": ["WS-042"], "checked_and_clean": ["DC01"]},
       "indicators": [{"type": "domain", "value": "cdn-sync-api.example", "why": "C2"}],
       "escalate_to_human": False}
PLAN = {"actions": [
    {"action": "isolate_host", "target": "WS-042", "policy": "allowed", "requires_approval": True,
     "approval_id": "APR-1", "reason": "C2"},
    {"action": "isolate_host", "target": "DC01", "policy": "blocked", "policy_reason": "Tier 0", "reason": "x"}]}


def test_ticket_sections_status_and_priority(monkeypatch):
    monkeypatch.setenv("SCENARIO", "A2")
    r = build_report({"alert_id": "ALR-A2-001"}, INV, PLAN, "ALR-A2-001-abc")
    assert r["priority"] == "P2" and r["status"] == "pending_approval" and r["case_id"] == "CASE-2002"
    md = r["report_markdown"]
    for section in ("**Timeline (UTC)**", "**Waiting for approval**", "**Blocked by policy:**"):
        assert section in md
    assert "APR-1" in md and "Tier 0" in md and "A2-EDR-00035" in md


def test_status_for_benign_and_critical():
    assert build_report({}, {"verdict": "benign_true_positive"}, {}, "i")["status"] == "closed_benign"
    assert build_report({}, {"verdict": "true_positive", "severity": "critical"}, {}, "i")["status"] == "escalated"


def test_redacts_password_patterns_and_known_secrets(monkeypatch):
    text, n = redact("svc pwd: Autumn#2026! and later Autumn#2026! again; api_key=abcd1234efgh", ["Autumn#2026!"])
    assert "Autumn#2026!" not in text and "abcd1234efgh" not in text and n >= 3
    monkeypatch.setenv("SCENARIO", "S4")
    report = redact_report({"report_markdown": "description holds Autumn#2026! for svc-legacyapp"})
    assert "Autumn#2026!" not in report["report_markdown"] and report["redactions"] == 1


def test_reporter_is_plain_code():
    agent = build_reporter_agent()
    assert agent.name == "reporter" and not hasattr(agent, "model")
