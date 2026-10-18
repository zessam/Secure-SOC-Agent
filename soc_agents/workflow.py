"""Incident workflow: Triage -> parallel specialists -> Investigator (-> Planner, Reporter next)."""
from __future__ import annotations

from google.adk.agents import SequentialAgent

from .investigator import build_investigator_agent
from .specialists import build_specialists
from .triage import build_triage_agent


def build_incident_workflow() -> SequentialAgent:
    return SequentialAgent(
        name="incident_workflow",
        description="Handles one SOC alert end to end.",
        sub_agents=[build_triage_agent(), build_specialists(), build_investigator_agent()],
    )
