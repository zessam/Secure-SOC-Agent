"""Basic guardrails shared by agents (fuller policy engine comes in Phase 4)."""
from __future__ import annotations

from typing import Any


def tool_budget(max_calls: int):
    """Stop an agent after max_calls tool calls per run (invocation), so it cannot loop or read everything."""

    def before_tool(tool, args: dict[str, Any], tool_context) -> dict | None:
        key = f"temp:tool_calls:{tool_context.invocation_id}:{tool_context.agent_name}"
        used = tool_context.state.get(key, 0)
        if used >= max_calls:
            return {"error": f"Tool budget of {max_calls} calls used. Give your answer now with the evidence you have."}
        tool_context.state[key] = used + 1
        return None

    return before_tool
