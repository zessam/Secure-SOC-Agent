"""Run the incident workflow (Triage -> specialists ...) on one scenario and save every agent's output.

    .venv/bin/python scripts/run_incident.py --scenario A2
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env", override=True)

OUTPUT_KEYS = ["triage", "siem_findings", "edr_findings", "identity_findings", "threat_intel_findings",
               "investigation"]


async def main(scenario: str) -> None:
    os.environ["SCENARIO"] = scenario
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    from mcp_servers.common.store import ScenarioStore
    from soc_agents.common.models import get_model
    from soc_agents.workflow import build_incident_workflow

    store = ScenarioStore(scenario)
    if not store.alerts:
        sys.exit(f"Scenario {scenario} has no alert (it is an analyst question); use the copilot instead.")
    alert_id = store.alerts[0]["alert_id"]
    m = get_model("flash")
    print(f"== {scenario} / {alert_id}  model: {m if isinstance(m, str) else f'vLLM {m.model} @ {m.base_url}'}")

    workflow = build_incident_workflow()
    runner = InMemoryRunner(agent=workflow, app_name="soc")
    session = await runner.session_service.create_session(app_name="soc", user_id="analyst")
    message = types.Content(role="user", parts=[types.Part(text=f"New SIEM alert {alert_id}. Triage it.")])
    try:
        async for event in runner.run_async(user_id="analyst", session_id=session.id, new_message=message):
            for part in (event.content.parts if event.content else []) or []:
                if part.function_call:
                    print(f"  [{event.author}] -> {part.function_call.name}({json.dumps(part.function_call.args)[:160]})")
            if event.error_message:
                print(f"  [{event.author}] ERROR {event.error_message[:300]}")
    finally:
        await runner.close()

    session = await runner.session_service.get_session(app_name="soc", user_id="analyst", session_id=session.id)
    results = {k: session.state.get(k) for k in OUTPUT_KEYS}
    for k, v in results.items():
        print(f"\n===== {k} =====\n{json.dumps(v, indent=2)}")
    # Citation check (plain code): every event id an agent cites must exist in the scenario data.
    import re
    cited = sorted(set(re.findall(rf"{scenario}-(?:SIEM|EDR)-\d{{5}}", json.dumps(results))))
    unknown = [i for i in cited if store.event_by_id(i) is None]
    print(f"\ncitation check: {len(cited)} event ids cited, {len(unknown)} not found {unknown if unknown else ''}")
    results["citation_check"] = {"cited": len(cited), "not_found": unknown}

    out = ROOT / "runs" / f"{scenario}-incident-{datetime.now():%Y%m%d-%H%M%S}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"scenario": scenario, "alert_id": alert_id, **results}, indent=2))
    print(f"\nsaved {out.relative_to(ROOT)}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default="A2")
    asyncio.run(main(p.parse_args().scenario.upper()))
