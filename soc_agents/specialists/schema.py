"""Output shared by all specialists, saved as `<name>_findings`."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from ..common.schemas import AgentOutput, Finding, Indicator


class SpecialistFindings(AgentOutput):
    specialist: Literal["siem", "edr", "identity", "threat_intel"]
    summary: str = Field(description="3-5 sentences answering triage's questions for your system")
    malicious_activity_found: bool
    findings: list[Finding]
    indicators: list[Indicator] = Field(default_factory=list, description="Only suspicious IOCs, never signed system binaries or internal IPs")
    affected_users: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    benign_explanations: list[str] = Field(default_factory=list, description="Evidence that points to legitimate activity")
    gaps: list[str] = Field(default_factory=list, description="Questions you could not answer and why")
