"""Mock MCP servers: each tool is exercised through a real MCP client (in-process transport)."""
from __future__ import annotations

import asyncio
import json

import pytest
from mcp import Client

from mcp_servers import ad_mcp, case_mcp, edr_read_mcp, siem_mcp, ti_mcp
from mcp_servers.common.store import ScenarioStore

SERVERS = (siem_mcp, edr_read_mcp, ad_mcp, ti_mcp, case_mcp)


def call(module, scenario: str, tool: str, **args) -> dict:
    async def run():
        async with Client(module.build_server(ScenarioStore(scenario))) as client:
            result = await client.call_tool(tool, args)
            assert not result.is_error, result.content
            return json.loads(result.content[0].text)
    return asyncio.run(run())


def tool_names(module) -> dict:
    async def run():
        async with Client(module.build_server(ScenarioStore("A2"))) as client:
            return {t.name: t for t in (await client.list_tools()).tools}
    return asyncio.run(run())


# ---- safety ---------------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", ["A1", "A2", "A4", "A7", "S4", "S8"])
def test_store_never_reads_ground_truth_or_narrative(scenario):
    store = ScenarioStore(scenario)
    read = " ".join(store.files_read)
    assert "expected.yaml" not in read
    assert "scenario.yaml" not in read
    with pytest.raises(PermissionError):
        store._path(store.folders[0], "expected.yaml")


@pytest.mark.parametrize("module", SERVERS)
def test_all_tools_are_annotated_read_only(module):
    for name, tool in tool_names(module).items():
        assert tool.annotations and tool.annotations.read_only_hint, name
        assert not tool.annotations.destructive_hint, name


def test_search_is_capped_at_50_with_total_count():
    res = call(siem_mcp, "A2", "search_events", limit=500)
    assert res["returned"] == 50
    assert res["total_matched"] > 50
    assert res["truncated"] is True


def test_unknown_scenario_is_rejected():
    with pytest.raises(ValueError):
        ScenarioStore("Z9")


# ---- A2: macro -> encoded PowerShell -> C2 ----------------------------------------------------

def test_a2_alert_points_at_ws042():
    alert = call(siem_mcp, "A2", "get_alert", alert_id="ALR-A2-001")
    assert alert["entities"]["hosts"] == ["WS-042"]


def test_a2_process_tree_outlook_word_powershell_payload():
    tree = call(edr_read_mcp, "A2", "get_process_tree", host="WS-042", process_name="powershell.exe")
    assert [a["name"] for a in tree["ancestors"]][-2:] == ["OUTLOOK.EXE", "WINWORD.EXE"]
    ps = tree["process"]
    assert "-Enc" in ps["command_line"]
    payload = ps["children"][0]
    assert payload["name"] == "svchost-update.exe"
    assert payload["signed_trusted"] is False
    assert any(a.get("registry.key", "").endswith("CurrentVersion\\Run") for a in payload["activity"])


def test_a2_connections_show_c2_domain_and_ti_says_malicious():
    conns = call(edr_read_mcp, "A2", "host_connections", host="WS-042")
    domains = {d.get("domain") for d in conns["destinations"]}
    assert "cdn-sync-api.example" in domains
    ti = call(ti_mcp, "A2", "lookup_indicators", indicators=["cdn-sync-api.example", "10.10.5.42", "8.8.8.8"])
    verdicts = {r["indicator"]: r["verdict"] for r in ti["results"]}
    assert verdicts == {"cdn-sync-api.example": "malicious", "10.10.5.42": "internal", "8.8.8.8": "unknown"}


def test_a2_cited_events_resolve():
    res = call(edr_read_mcp, "A2", "get_events", event_ids=["A2-EDR-00035", "A2-EDR-99999", "A2-SIEM-00001"])
    assert [e["event"]["id"] for e in res["events"]] == ["A2-EDR-00035"]
    assert res["not_found"] == ["A2-EDR-99999", "A2-SIEM-00001"]


# ---- A1: phishing -> MFA fatigue -> inbox rule ---------------------------------------------

def test_a1_mfa_fatigue_visible_in_signin_history():
    res = call(ad_mcp, "A1", "signin_history", user="j.smith", limit=50)
    mfa = [e for e in res["events"] if e["event"]["dataset"] == "azuread.mfa"]
    assert {e["event"]["outcome"] for e in mfa} >= {"denied", "success"}
    assert any(b["value"] == "203.0.113.88" for b in res["summary"]["by_source_ip"])


def test_a1_inbox_rule_forwards_externally():
    res = call(siem_mcp, "A1", "search_events", user="j.smith", dataset="o365.audit", action="New-InboxRule")
    rule = res["events"][0]
    assert rule["o365"]["actions"]["forward_to"] == "j.smith.archive@mailbox.example"


# ---- A4: false positive covered by a change ------------------------------------------------

def test_a4_change_window_covers_activity():
    inside = call(case_mcp, "A4", "search_changes", host="WS-015", at_time="2026-10-13T14:30:00Z")
    assert [c["number"] for c in inside["changes"]] == ["CHG0041872"]
    outside = call(case_mcp, "A4", "search_changes", host="WS-015", at_time="2026-10-13T18:00:00Z")
    assert outside["total_matched"] == 0


# ---- scale and identity cases --------------------------------------------------------------

def test_a3_spray_summarised_by_aggregation():
    res = call(siem_mcp, "A3", "aggregate_events", group_by="user.name", ip="203.0.113.66",
               dataset="azuread.signin")
    assert res["distinct_values"] >= 20
    ok = call(siem_mcp, "A3", "search_events", ip="203.0.113.66", outcome="success", dataset="azuread.signin")
    assert {e["user"]["name"] for e in ok["events"]} == {"p.garcia"}


def test_a6_indicator_seen_on_three_hosts():
    res = call(edr_read_mcp, "A6", "find_indicator", indicator="cdn-telemetry-sync.example")
    hosts = {h["value"] for h in res["hosts"]}
    assert "WS-019" in hosts


def test_a7_domain_admins_change_reflected():
    user = call(ad_mcp, "A7", "get_user", username="m.chen")
    assert "Domain Admins" in user["privileged_groups"]
    group = call(ad_mcp, "A7", "get_group", group="Domain Admins")
    assert "m.chen" in group["members"]
    changes = call(ad_mcp, "A7", "directory_changes", user="m.chen", group="Domain Admins")
    assert changes["events"][0]["user"]["name"] == "svc-backup"


def test_s8_alert_flood_is_paged():
    res = call(siem_mcp, "S8", "list_alerts", limit=100)
    assert res["total_matched"] == 200
    assert res["returned"] == 50


# ---- ALL mode: every scenario loaded at once -----------------------------------------------

def test_all_mode_loads_every_scenario():
    store = ScenarioStore("ALL")
    assert len(store.folders) == 14
    assert "expected.yaml" not in " ".join(store.files_read)
    assert len(store.alerts) == sum(len(ScenarioStore(s).alerts) for s in ("A1", "A2", "S8")) + \
        sum(len(ScenarioStore(s).alerts) for s in ("A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "S1", "S2", "S4"))


def test_all_mode_cases_and_cross_scenario_lookups():
    assert call(case_mcp, "ALL", "get_case", case_id="CASE-2002")["case_id"] == "CASE-2002"
    assert call(case_mcp, "ALL", "get_case", case_id="CASE-1023")["case_id"] == "CASE-1023"
    assert "cases" in call(case_mcp, "ALL", "get_case")
    assert call(siem_mcp, "ALL", "get_alert", alert_id="ALR-A4-001")["entities"]["users"] == ["a.patel"]
    assert "Domain Admins" in call(ad_mcp, "ALL", "get_user", username="m.chen")["privileged_groups"]
