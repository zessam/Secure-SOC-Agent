"""Specialists run in parallel after Triage; each one investigates a single system (read-only)."""
from __future__ import annotations

from google.adk.agents import ParallelAgent

from . import edr, identity, siem, threat_intel


def build_specialists() -> ParallelAgent:
    return ParallelAgent(
        name="specialists",
        description="SIEM, EDR, Identity and Threat Intel specialists investigating in parallel.",
        sub_agents=[siem.build(), edr.build(), identity.build(), threat_intel.build()],
    )


__all__ = ["build_specialists"]
