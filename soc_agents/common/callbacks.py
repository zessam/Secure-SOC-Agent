"""Basic guardrails shared by agents (fuller policy engine comes in Phase 4)."""
from __future__ import annotations

from typing import Any

# ADK's built-in tool an agent calls to submit its structured final answer (output_schema).
# It must never be blocked, or the agent cannot finish and replies with invalid plain text.
FINAL_ANSWER_TOOL = "set_model_response"


def tool_budget(max_calls: int):
    """Stop an agent after max_calls tool calls per run (invocation), so it cannot loop or read everything."""

    def before_tool(tool, args: dict[str, Any], tool_context) -> dict | None:
        if tool.name == FINAL_ANSWER_TOOL:
            return None
        key = f"temp:tool_calls:{tool_context.invocation_id}:{tool_context.agent_name}"
        used = tool_context.state.get(key, 0)
        if used >= max_calls:
            return {"error": (f"Tool budget of {max_calls} calls is used up. Do not call any more investigation "
                              f"tools. Submit your final answer now by calling {FINAL_ANSWER_TOOL} with the "
                              "evidence you already have, and list what you could not check under gaps.")}
        tool_context.state[key] = used + 1
        return None

    return before_tool
