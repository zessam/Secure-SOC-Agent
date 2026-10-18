from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def runs_dir() -> Path:
    d = Path(os.environ.get("SOC_RUNS_DIR") or ROOT / "runs")
    d.mkdir(parents=True, exist_ok=True)
    return d


def approvals_db() -> Path:
    return Path(os.environ.get("SOC_APPROVALS_DB") or runs_dir() / "approvals.db")
