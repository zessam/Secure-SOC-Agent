"""Triage output, saved in session state as `triage`."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from ..common.schemas import AgentOutput, Entities, TimeWindow


class TriageResult(AgentOutput):
    alert_id: str
    summary: str = Field(description="2-3 sentences: what the alert says happened, to whom, where")
    alert_type: str = Field(description="e.g. malware, phishing, credential_attack, privilege_change, data_exfil")
    severity: Literal["low", "medium", "high", "critical"]
    severity_reason: str
    entities: Entities
    time_window: TimeWindow
    hypotheses: list[str] = Field(description="Most likely explanations, malicious and benign")
    evidence_event_ids: list[str] = Field(description="Event ids you actually looked at")
    specialists_needed: list[Literal["siem", "edr", "identity", "threat_intel"]]
    questions_for_specialists: list[str] = Field(description="Concrete questions the specialists should answer")
    benign_indicators: list[str] = Field(default_factory=list,
                                         description="Signs this may be legitimate, e.g. an approved change")
    escalate_to_human: bool
    escalate_reason: str | None = None
