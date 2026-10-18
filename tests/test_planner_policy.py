"""Policy review of proposed actions: the 'must NOT do' cases from the scenario answer keys."""
from __future__ import annotations

import asyncio

from soc_agents.planner import build_planner_agent
from soc_agents.planner.policy import review_plan

EV = ["A2-EDR-00039"]


def act(action, target, evidence=EV):
    return {"action": action, "target": target, "reason": "r", "evidence_event_ids": evidence, "urgency": "immediate"}


def decide(plan_actions, investigation, signed=None):
    reviewed = review_plan({"summary": "s", "actions": plan_actions, "close_case": False}, investigation, signed)
    return {(a["action"], a["target"]): a for a in reviewed["actions"]}, reviewed


A2_INV = {
    "severity": "high", "escalate_to_human": False,
    "scope": {"compromised_users": ["s.khan"], "compromised_hosts": ["WS-042"], "checked_and_clean": ["DC01"]},
    "indicators": [{"value": "cdn-sync-api.example"}, {"value": "203.0.113.201"},
                   {"value": "601c50a4dd82fefd1cc463f4dd4dfd008151594759dea2fde6a0faf26a71fc37"}],
}


def test_a2_good_plan_allowed_and_needs_approval():
    d, reviewed = decide([act("isolate_host", "WS-042"), act("block_domain", "cdn-sync-api.example"),
                          act("block_ip", "203.0.113.201"), act("reset_password", "s.khan")], A2_INV)
    assert all(a["policy"] == "allowed" and a["requires_approval"] for a in d.values())
    assert reviewed["policy_summary"] == {"allowed_needing_approval": 4, "allowed_auto": 0, "blocked": 0}


def test_domain_controller_never_isolated():
    d, _ = decide([act("isolate_host", "DC01")], A2_INV)
    assert d[("isolate_host", "DC01")]["policy"] == "blocked"
    assert "Tier 0" in d[("isolate_host", "DC01")]["policy_reason"]


def test_a6_clean_hosts_not_isolated_but_scan_allowed():
    inv = {"scope": {"compromised_hosts": ["WS-019"], "checked_and_clean": ["WS-033", "WS-050"]}, "indicators": []}
    d, _ = decide([act("isolate_host", "WS-019"), act("isolate_host", "WS-033"), act("isolate_host", "WS-050"),
                   act("run_av_scan", "WS-033")], inv)
    assert d[("isolate_host", "WS-019")]["policy"] == "allowed"
    assert d[("isolate_host", "WS-033")]["policy"] == "blocked"
    assert d[("isolate_host", "WS-050")]["policy"] == "blocked"
    assert d[("run_av_scan", "WS-033")]["policy"] == "allowed"
    assert d[("run_av_scan", "WS-033")]["requires_approval"] is False


def test_s2_blast_radius_over_10_users_blocked():
    users = [f"user{i}" for i in range(12)]
    d, _ = decide([act("reset_password", u) for u in users], {"scope": {"compromised_users": users}})
    assert all(a["policy"] == "blocked" for a in d.values())
    d, _ = decide([act("disable_user", "all-staff")], {})
    assert d[("disable_user", "all-staff")]["policy"] == "blocked"


def test_protected_domains_ips_and_signed_hashes():
    signed = {"f307e73a3447b10444e67233700c1aa5ca8e3673dd2f292084bf485583caad6f"}  # powershell.exe
    d, _ = decide([act("block_domain", "contoso.sharepoint.com"), act("block_ip", "10.10.5.42"),
                   act("block_ip", "198.51.100.10"), act("block_hash", next(iter(signed)))], {}, signed)
    assert all(a["policy"] == "blocked" for a in d.values())


def test_ioc_must_be_confirmed_and_evidence_required():
    d, _ = decide([act("block_ip", "203.0.113.250"), act("isolate_host", "WS-042", evidence=[])], A2_INV)
    assert d[("block_ip", "203.0.113.250")]["policy"] == "blocked"
    assert d[("isolate_host", "WS-042")]["policy_reason"] == "no evidence cited"


def test_critical_incident_always_escalated():
    inv = {"severity": "critical", "escalate_to_human": True,
           "scope": {"compromised_users": ["m.chen"], "compromised_hosts": ["WS-058"]}}
    d, _ = decide([act("remove_group_member", "m.chen from Domain Admins")], inv)
    assert ("escalate", "Incident Response") in d
    assert d[("remove_group_member", "m.chen from Domain Admins")]["requires_approval"] is True


def test_planner_wiring(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    monkeypatch.setenv("SCENARIO", "A2")
    agent = build_planner_agent()

    async def names():
        out = []
        for ts in agent.tools:
            out += [t.name for t in await ts.get_tools_with_prefix()]
            await ts.close()
        return sorted(out)

    assert asyncio.run(names()) == ["ad_get_host", "ad_get_user"]
    assert agent.output_key == "response_plan" and agent.after_agent_callback is not None
    assert "{investigation}" in agent.instruction
