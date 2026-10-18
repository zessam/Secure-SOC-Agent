"""Durable human-approval queue (SQLite).

Each action of a policy-reviewed response plan becomes a request:
  policy blocked             -> status "blocked"        (kept for audit, can never run)
  low impact (no approval)   -> status "auto_approved"  (decided_by "policy")
  high impact                -> status "pending"        (a named human must approve or reject)
Executor marks requests "executed" or "failed".
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from . import audit
from .paths import approvals_db

EXECUTABLE = ("approved", "auto_approved")
NON_HUMAN = {"", "system", "agent", "ai", "executor", "policy", "planner", "copilot"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  reason TEXT, evidence TEXT, urgency TEXT, requires_approval INTEGER, policy_reason TEXT,
  status TEXT NOT NULL, created_at TEXT, decided_by TEXT, decided_at TEXT, comment TEXT,
  executed_at TEXT, result TEXT
)"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(approvals_db())
    con.row_factory = sqlite3.Row
    con.execute(_SCHEMA)
    return con


def _row(r: sqlite3.Row | None) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    d["evidence"] = json.loads(d["evidence"] or "[]")
    d["result"] = json.loads(d["result"]) if d["result"] else None
    return d


def submit_plan(incident_id: str, response_plan: dict) -> list[dict]:
    """Queue every action of a policy-reviewed plan. Returns the created requests."""
    created = []
    with _conn() as con:
        for a in response_plan.get("actions", []):
            if a.get("policy") == "blocked":
                status, decided_by = "blocked", "policy"
            elif not a.get("requires_approval", True):
                status, decided_by = "auto_approved", "policy"
            else:
                status, decided_by = "pending", None
            rid = "APR-" + uuid.uuid4().hex[:8].upper()
            con.execute(
                "INSERT INTO requests (id, incident_id, action, target, reason, evidence, urgency, requires_approval,"
                " policy_reason, status, created_at, decided_by, decided_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, incident_id, a["action"], a["target"], a.get("reason"), json.dumps(a.get("evidence_event_ids", [])),
                 a.get("urgency"), int(bool(a.get("requires_approval", True))), a.get("policy_reason"), status, _now(),
                 decided_by, _now() if decided_by else None))
            created.append(get(rid, con))
    audit.log("planner", "plan_submitted", incident_id=incident_id,
              counts={s: sum(r["status"] == s for r in created) for s in ("pending", "auto_approved", "blocked")})
    return created


def get(request_id: str, con: sqlite3.Connection | None = None) -> dict | None:
    con = con or _conn()
    return _row(con.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone())


def list_requests(incident_id: str | None = None, status: str | None = None) -> list[dict]:
    q, args = "SELECT * FROM requests WHERE 1=1", []
    if incident_id:
        q, args = q + " AND incident_id = ?", args + [incident_id]
    if status:
        q, args = q + " AND status = ?", args + [status]
    with _conn() as con:
        return [_row(r) for r in con.execute(q + " ORDER BY created_at, rowid", args)]


def decide(request_id: str, approver: str, approve: bool, comment: str = "") -> dict:
    """A named human approves or rejects a pending request."""
    if approver.strip().lower() in NON_HUMAN:
        raise PermissionError("approvals must be made by a named human analyst")
    with _conn() as con:
        req = get(request_id, con)
        if not req:
            raise KeyError(f"no request {request_id}")
        if req["status"] != "pending":
            raise ValueError(f"{request_id} is {req['status']}; only pending requests can be decided")
        if not approve and not comment:
            raise ValueError("a rejection needs a comment explaining why")
        status = "approved" if approve else "rejected"
        con.execute("UPDATE requests SET status=?, decided_by=?, decided_at=?, comment=? WHERE id=?",
                    (status, approver, _now(), comment, request_id))
        req = get(request_id, con)
    audit.log(approver, f"request_{status}", incident_id=req["incident_id"], request_id=request_id,
              action=req["action"], target=req["target"], comment=comment)
    return req


def mark_executed(request_id: str, ok: bool, result: dict) -> None:
    with _conn() as con:
        con.execute("UPDATE requests SET status=?, executed_at=?, result=? WHERE id=?",
                    ("executed" if ok else "failed", _now(), json.dumps(result), request_id))


def check_executable(request_id: str, action: str, target: str) -> tuple[bool, str]:
    """Used by the write servers: is this exact action/target approved and not yet run?"""
    req = get(request_id)
    if not req:
        return False, "unknown approval id"
    if req["status"] not in EXECUTABLE:
        return False, f"approval {request_id} is {req['status']}"
    if req["action"] != action or req["target"] != target:
        return False, f"approval {request_id} is for {req['action']} on {req['target']}, not {action} on {target}"
    return True, "ok"
