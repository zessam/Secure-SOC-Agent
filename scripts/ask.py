"""Ask the Analyst Copilot a question from the command line.

    .venv/bin/python scripts/ask.py "What did host WS-023 do yesterday?"
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env", override=True)


async def main(scenario: str, question: str) -> None:
    os.environ["SCENARIO"] = scenario
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    from soc_agents.copilot import build_copilot_agent

    agent = build_copilot_agent()
    m = agent.model
    print(f"== copilot on {scenario}  model: {getattr(m, 'model', m)}{' @ ' + m.base_url if getattr(m, 'base_url', None) else ''}")
    runner = InMemoryRunner(agent=agent, app_name="soc")
    session = await runner.session_service.create_session(app_name="soc", user_id="analyst")
    try:
        async for event in runner.run_async(user_id="analyst", session_id=session.id,
                                            new_message=types.Content(role="user", parts=[types.Part(text=question)])):
            for part in (event.content.parts if event.content else []) or []:
                if part.function_call:
                    print(f"  [{event.author}] -> {part.function_call.name}({json.dumps(part.function_call.args)[:160]})")
                elif part.text and event.author == "analyst_copilot" and not event.partial:
                    print(f"\n{part.text}")
            if event.error_message:
                print(f"  [{event.author}] ERROR {event.error_message[:300]}")
    finally:
        await runner.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default="ALL", help="lab dataset the systems serve (default ALL = every scenario)")
    p.add_argument("question")
    a = p.parse_args()
    asyncio.run(main(a.scenario.upper(), a.question))
