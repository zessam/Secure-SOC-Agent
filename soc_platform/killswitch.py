"""Kill switch: when engaged, the Executor and the write servers refuse every action.

Engage with:  SOC_KILL_SWITCH=1   or   python scripts/approvals.py kill-switch on   (creates runs/KILL_SWITCH)
"""
from __future__ import annotations

import os

from . import audit
from .paths import runs_dir


def _flag():
    return runs_dir() / "KILL_SWITCH"


def engaged() -> bool:
    return os.environ.get("SOC_KILL_SWITCH", "").lower() in ("1", "true", "on") or _flag().exists()


def engage(by: str, reason: str = "") -> None:
    _flag().write_text(f"{by}: {reason}\n", encoding="utf-8")
    audit.log(by, "kill_switch_engaged", reason=reason)


def release(by: str) -> None:
    if _flag().exists():
        _flag().unlink()
    audit.log(by, "kill_switch_released")
