"""adk web entry point:  SCENARIO=A2 .venv/bin/adk web --port 8080 adk_apps  (pick incident_workflow)"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env", override=True)

from soc_agents.workflow import build_incident_workflow  # noqa: E402

root_agent = build_incident_workflow()
