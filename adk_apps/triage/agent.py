"""adk web entry point:  SCENARIO=A2 .venv/bin/adk web --port 8080 adk_apps"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env", override=True)  # project .env decides the model provider

from soc_agents.triage import build_triage_agent  # noqa: E402

root_agent = build_triage_agent()
_m = root_agent.model
print(f"[triage] model: {_m if isinstance(_m, str) else f'vLLM {_m.model} @ {_m.base_url}'}", file=sys.stderr)
