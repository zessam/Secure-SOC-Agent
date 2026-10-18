"""Response Planner: proposes actions; policy.py then reviews them in code before human approval."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from ..common.callbacks import tool_budget
from ..common.models import get_model
from ..common.tools import mcp_tools
from .policy import review_plan
from .prompt import INSTRUCTION
from .schema import ResponsePlan


def _signed_hashes(investigation: dict) -> set[str]:
    """Hashes the EDR reports as signed/trusted (in production: an EDR / allow-list lookup)."""
    try:
        from mcp_servers.common.store import ScenarioStore  # mock EDR data in this lab
        return {e["process"]["hash"]["sha256"] for e in ScenarioStore().edr_events
                if e.get("process", {}).get("code_signature", {}).get("trusted") and
                e.get("process", {}).get("hash", {}).get("sha256")}
    except Exception:  # noqa: BLE001 - policy must still run without the lab data
        return set()


def apply_policy(callback_context):
    """after_agent_callback: policy-review the plan, then queue it for human approval (plain code)."""
    plan = callback_context.state.get("response_plan")
    if not isinstance(plan, dict):
        return None
    investigation = callback_context.state.get("investigation") or {}
    reviewed = review_plan(plan, investigation, _signed_hashes(investigation))
    triage = callback_context.state.get("triage") or {}
    incident_id = f"{triage.get('alert_id', 'INC')}-{callback_context.invocation_id[-6:]}"
    from soc_platform import approvals
    queued = approvals.submit_plan(incident_id, reviewed)
    by_key = {(q["action"], q["target"]): q for q in queued}
    for a in reviewed["actions"]:
        q = by_key.get((a["action"], a["target"]))
        if q:
            a["approval_id"], a["approval_status"] = q["id"], q["status"]
    callback_context.state["incident_id"] = incident_id
    callback_context.state["response_plan"] = reviewed
    return None


def build_planner_agent() -> LlmAgent:
    return LlmAgent(
        name="response_planner",
        description="Proposes containment and recovery actions (never executes); reviewed by policy code.",
        model=get_model("pro"),
        instruction=INSTRUCTION,
        tools=[mcp_tools("ad_mcp", ["get_host", "get_user"])],  # check tier / account type before proposing
        output_schema=ResponsePlan,
        output_key="response_plan",
        before_tool_callback=tool_budget(4),
        after_agent_callback=apply_policy,
    )
