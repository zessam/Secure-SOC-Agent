"""Response Planner output, saved in session state as `response_plan` (then reviewed by policy.py)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..common.schemas import AgentOutput

ActionType = Literal[
    # containment
    "isolate_host", "kill_process", "quarantine_file",
    "block_ip", "block_domain", "block_hash", "block_sender_domain", "purge_email",
    # identity
    "reset_password", "revoke_sessions", "disable_user", "remove_group_member",
    "remove_inbox_rule", "disable_legacy_auth", "clear_ad_description",
    # low impact / process
    "run_av_scan", "contact_user", "escalate", "close_case", "propose_detection_tuning",
]


class ProposedAction(BaseModel):
    action: ActionType
    target: str = Field(description="Exactly one host, user, IP, domain, hash, group change or case id")
    reason: str = Field(description="Max 10 words")
    evidence_event_ids: list[str] = Field(description="1-2 event ids")
    urgency: Literal["immediate", "soon", "later"]


class NotRecommended(BaseModel):
    action: str
    target: str
    reason: str = Field(description="Max 10 words")


class ResponsePlan(AgentOutput):
    summary: str = Field(description="One sentence, max 25 words")
    actions: list[ProposedAction]
    not_recommended: list[NotRecommended] = Field(
        default_factory=list, description="Max 3 over-reactions you rejected (e.g. isolating a clean host)")
    close_case: bool = Field(description="True only for false/benign positives with nothing to contain")
