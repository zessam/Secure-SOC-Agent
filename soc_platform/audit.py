"""Append-only audit log (JSON lines): who did what, when, to which target, with what result."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .paths import runs_dir


def audit_file():
    return runs_dir() / "audit.jsonl"


def log(actor: str, event: str, **details: Any) -> None:
    entry = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "actor": actor, "event": event,
             **details}
    with audit_file().open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")


def read(incident_id: str | None = None) -> list[dict]:
    if not audit_file().exists():
        return []
    rows = [json.loads(line) for line in audit_file().read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if not incident_id or r.get("incident_id") == incident_id]
