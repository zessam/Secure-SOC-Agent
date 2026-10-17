"""Triage agent wiring (no LLM calls): tools, least privilege, model selection, vLLM payload."""
from __future__ import annotations

import asyncio

from google.adk.models.llm_request import LlmRequest
from google.genai import types

from soc_agents import models
from soc_agents.triage import build_triage_agent


def test_triage_sees_only_allowed_read_tools(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "gemini")
    monkeypatch.setenv("SCENARIO", "A2")
    agent = build_triage_agent()

    async def names():
        out = []
        for ts in agent.tools:
            out += [t.name for t in await ts.get_tools_with_prefix()]
            await ts.close()
        return sorted(out)

    assert asyncio.run(names()) == sorted([
        "siem_get_alert", "siem_get_events", "siem_list_alerts", "edr_get_events",
        "ad_get_user", "ad_get_host", "case_get_case", "case_search_changes",
    ])


def test_vllm_provider_builds_openai_payload(monkeypatch):
    monkeypatch.setenv("SOC_MODEL_PROVIDER", "vllm")
    monkeypatch.setenv("VLLM_MODEL", "Qwen/Qwen3-32B")
    llm = models.get_model("pro")
    assert isinstance(llm, models.VllmLlm)
    client = models._VllmClient(llm.model, base_url=llm.base_url)
    req = LlmRequest(
        model=llm.model,
        contents=[types.Content(role="user", parts=[types.Part(text="Triage ALR-A2-001")])],
        config=types.GenerateContentConfig(
            system_instruction="You are triage.",
            tools=[types.Tool(function_declarations=[types.FunctionDeclaration(
                name="siem_get_alert", description="get alert",
                parameters_json_schema={"type": "object", "properties": {"alert_id": {"type": "string"}}})])],
        ),
    )
    payload = client._construct_payload(req, stream=False)
    assert payload["model"] == "Qwen/Qwen3-32B"
    assert payload["messages"][0] == {"role": "system", "content": "You are triage."}
    assert payload["tools"][0]["function"]["name"] == "siem_get_alert"
