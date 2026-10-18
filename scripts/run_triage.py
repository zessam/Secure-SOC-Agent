"""Run the Triage agent on one scenario's alert and save the result.

    .venv/bin/python scripts/run_triage.py --scenario A2
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


async def main(scenario: str) -> None:
    os.environ["SCENARIO"] = scenario
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    from mcp_servers.common.store import ScenarioStore
    from soc_agents.triage import build_triage_agent

    # Intake (plain code): the SIEM pushes the alert id; the agent fetches the details itself.
    store = ScenarioStore(scenario)
    if not store.alerts:
        sys.exit(f"Scenario {scenario} has no alert (it is an analyst question); triage does not apply.")
    alert_id = store.alerts[0]["alert_id"]
    message = f"New SIEM alert {alert_id}. Triage it."

    agent = build_triage_agent()
    runner = InMemoryRunner(agent=agent, app_name="soc")
    session = await runner.session_service.create_session(app_name="soc", user_id="analyst")
    print(f"== Triage {scenario} / {alert_id}  (model: {getattr(agent.model, "model", agent.model)})")
    try:
        async for event in runner.run_async(user_id="analyst", session_id=session.id,
                                            new_message=types.Content(role="user", parts=[types.Part(text=message)])):
            for part in (event.content.parts if event.content else []) or []:
                if part.function_call:
                    print(f"  -> {part.function_call.name}({json.dumps(part.function_call.args)})")
    finally:
        await runner.close()

    session = await runner.session_service.get_session(app_name="soc", user_id="analyst", session_id=session.id)
    result = session.state.get("triage")
    print(json.dumps(result, indent=2))
    out = ROOT / "runs" / f"{scenario}-triage-{datetime.now():%Y%m%d-%H%M%S}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"scenario": scenario, "alert_id": alert_id, "triage": result}, indent=2))
    print(f"saved {out.relative_to(ROOT)}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default="A2")
    asyncio.run(main(p.parse_args().scenario.upper()))
