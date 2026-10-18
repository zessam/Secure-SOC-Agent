"""Reporter output, saved in session state as `incident_report`."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from ..common.schemas import AgentOutput


class IncidentReport(AgentOutput):
    case_id: str | None = Field(default=None, description="SOAR case id if one exists, e.g. CASE-2002")
    ticket_title: str = Field(description="Short title for the ITSM ticket")
    priority: Literal["P1", "P2", "P3", "P4"] = Field(description="P1 critical, P2 high, P3 medium, P4 low")
    status: Literal["pending_approval", "escalated", "closed_false_positive", "closed_benign", "monitoring"]
    short_description: str = Field(description="One sentence for the ticket list view")
    report_markdown: str = Field(description="Full ticket body in Markdown (sections listed in the instructions)")
    analyst_next_steps: list[str] = Field(description="What the human analyst should do next")
