"""Incident workflow: Triage -> parallel specialists -> Investigator -> Response Planner -> Reporter
(human approval + Executor come next)."""
from __future__ import annotations

from google.adk.agents import SequentialAgent

from .intake import intake_router
from .investigator import build_investigator_agent
from .planner import build_planner_agent
from .reporter import build_reporter_agent
from .specialists import build_specialists
from .triage import build_triage_agent


def build_incident_workflow() -> SequentialAgent:
    return SequentialAgent(
        name="incident_workflow",
        description="Handles one SOC alert end to end.",
        before_agent_callback=intake_router,  # plain code: alert -> run; approval commands -> handled without AI
        sub_agents=[build_triage_agent(), build_specialists(), build_investigator_agent(),
                    build_planner_agent(), build_reporter_agent()],
    )
