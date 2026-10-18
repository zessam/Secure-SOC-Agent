"""End-to-end workflow with a fake model (no LLM cost): state passing, policy, approval queue, ticket."""
from __future__ import annotations

import asyncio
from typing import AsyncGenerator

from google.adk.agents import LlmAgent
from google.adk.models._capabilities import LlmCapabilities
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from soc_agents.workflow import build_incident_workflow
from soc_platform import approvals

TRIAGE = {"alert_id": "ALR-A2-001", "summary": "Word spawned encoded PowerShell on WS-042.", "alert_type": "malware",
          "severity": "high", "severity_reason": "likely compromise", "entities": {"users": ["s.khan"], "hosts": ["WS-042"]},
          "time_window": {"start": "2026-10-13T09:00:00Z", "end": "2026-10-13T12:00:00Z"},
          "hypotheses": "macro malware",  # list sent as plain text: must be tolerated
          "evidence_event_ids": ["A2-EDR-00035"], "specialists_needed": ["edr", "threat_intel"],
          "questions_for_specialists": ["EDR: what ran?"], "escalate_to_human": False}
FINDINGS = {"summary": "s", "malicious_activity_found": True,
            "findings": [{"statement": "payload ran", "evidence_event_ids": ["A2-EDR-00039"], "confidence": "high"}]}
INVESTIGATION = {"title": "Macro malware on WS-042", "verdict": "true_positive", "confidence": "high", "severity": "high",
                 "summary": "s.khan opened a malicious invoice.", "mitre_attack": ["T1059.001 PowerShell (Execution)"],
                 "attack_timeline": [{"time": "2026-10-13T10:16:05Z", "what_happened": "PowerShell",
                                      "evidence_event_ids": ["A2-EDR-00035"]}],
                 "scope": {"compromised_users": ["s.khan"], "compromised_hosts": ["WS-042"], "checked_and_clean": ["DC01"]},
                 "indicators": [{"value": "cdn-sync-api.example", "type": "domain", "why": "C2"}],
                 "what_needs_containing": ["WS-042"], "escalate_to_human": False}
PLAN = {"summary": "contain", "close_case": False, "actions": [
    {"action": "isolate_host", "target": "WS-042", "reason": "C2", "evidence_event_ids": ["A2-EDR-00039"], "urgency": "immediate"},
    {"action": "block_domain", "target": "cdn-sync-api.example", "reason": "C2", "evidence_event_ids": ["A2-EDR-00041"], "urgency": "immediate"},
    {"action": "isolate_host", "target": "DC01", "reason": "just in case", "evidence_event_ids": ["A2-EDR-00039"], "urgency": "soon"}]}


class FakeLlm(BaseLlm):
    seen: dict = {}

    @property
    def capabilities(self) -> LlmCapabilities:
        return LlmCapabilities(output_schema_and_tools=False)

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        instr = str(llm_request.config.system_instruction)
        if "You are the Triage agent" in instr:
            name, out = "triage", TRIAGE
        elif "You are the EDR specialist" in instr:
            name, out = "edr", {"specialist": "edr", **FINDINGS}
        elif "You are the Threat Intel specialist" in instr:
            name, out = "threat_intel", {"specialist": "threat_intel", **FINDINGS}
        elif "You are the Investigator" in instr:
            name, out = "investigator", INVESTIGATION
        elif "You are the Response Planner" in instr:
            name, out = "planner", PLAN
        else:
            raise AssertionError("unexpected agent: " + instr[:80])
        FakeLlm.seen[name] = instr
        yield LlmResponse(content=types.Content(role="model", parts=[
            types.Part(function_call=types.FunctionCall(name="set_model_response", args=out))]))


def _use_fake(agent):
    if isinstance(agent, LlmAgent):
        agent.model = FakeLlm(model="fake")
    for sub in agent.sub_agents:
        _use_fake(sub)


def test_full_workflow_a2(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_RUNS_DIR", str(tmp_path))
    monkeypatch.setenv("SCENARIO", "A2")
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    wf = build_incident_workflow()
    _use_fake(wf)

    async def run():
        runner = InMemoryRunner(agent=wf, app_name="soc")
        s = await runner.session_service.create_session(app_name="soc", user_id="u")
        msg = types.Content(role="user", parts=[types.Part(text="New SIEM alert ALR-A2-001. Triage it.")])
        async for _ in runner.run_async(user_id="u", session_id=s.id, new_message=msg):
            pass
        await runner.close()
        return (await runner.session_service.get_session(app_name="soc", user_id="u", session_id=s.id)).state

    state = asyncio.run(run())

    assert state["triage"]["hypotheses"] == ["macro malware"]
    assert state["identity_findings"]["summary"].startswith("Skipped")          # not requested by triage
    assert "ALR-A2-001" in FakeLlm.seen["edr"]                                   # triage injected into specialist
    assert "Macro malware on WS-042" in FakeLlm.seen["planner"]                  # investigation injected into planner

    decisions = {(a["action"], a["target"]): a["policy"] for a in state["response_plan"]["actions"]}
    assert decisions == {("isolate_host", "WS-042"): "allowed", ("block_domain", "cdn-sync-api.example"): "allowed",
                         ("isolate_host", "DC01"): "blocked"}
    queue = {(r["action"], r["target"]): r["status"] for r in approvals.list_requests(state["incident_id"])}
    assert queue[("isolate_host", "WS-042")] == "pending" and queue[("isolate_host", "DC01")] == "blocked"

    report = state["incident_report"]
    assert report["status"] == "pending_approval" and report["priority"] == "P2" and report["case_id"] == "CASE-2002"
    assert "## Blocked by policy" in report["report_markdown"]
