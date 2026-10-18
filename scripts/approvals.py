"""Analyst console for the approval queue and the Executor.

    .venv/bin/python scripts/approvals.py list [--incident ID] [--status pending]
    .venv/bin/python scripts/approvals.py show APR-1234ABCD
    .venv/bin/python scripts/approvals.py approve APR-1234ABCD --by "z.essam" [--comment "..."]
    .venv/bin/python scripts/approvals.py reject  APR-1234ABCD --by "z.essam" --comment "why"
    .venv/bin/python scripts/approvals.py execute INCIDENT_ID
    .venv/bin/python scripts/approvals.py audit [--incident ID]
    .venv/bin/python scripts/approvals.py kill-switch on|off|status [--by NAME] [--reason "..."]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soc_platform import approvals, audit, executor, killswitch  # noqa: E402

ICON = {"pending": "⏳", "approved": "✅", "auto_approved": "🤖", "rejected": "❌", "blocked": "⛔",
        "executed": "✔️ ", "failed": "💥"}


def show_table(rows: list[dict]) -> None:
    if not rows:
        print("(no requests)")
        return
    for r in rows:
        who = f" by {r['decided_by']}" if r["decided_by"] else ""
        print(f"{ICON.get(r['status'], '?')} {r['id']}  {r['incident_id']:<22} {r['status']:<13}{who:<16} "
              f"{r['action']:<22} {r['target']}")
        if r["status"] in ("pending", "blocked"):
            print(f"      why: {r['reason']}  | policy: {r['policy_reason']}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("list"); s.add_argument("--incident"); s.add_argument("--status")
    s = sub.add_parser("show"); s.add_argument("id")
    for name in ("approve", "reject"):
        s = sub.add_parser(name); s.add_argument("id"); s.add_argument("--by", required=True)
        s.add_argument("--comment", default="")
    s = sub.add_parser("approve-all", help="approve every pending request of an incident")
    s.add_argument("incident"); s.add_argument("--by", required=True); s.add_argument("--comment", default="")
    s = sub.add_parser("execute"); s.add_argument("incident")
    s = sub.add_parser("audit"); s.add_argument("--incident")
    s = sub.add_parser("kill-switch"); s.add_argument("state", choices=["on", "off", "status"])
    s.add_argument("--by", default="analyst"); s.add_argument("--reason", default="")
    a = p.parse_args()

    if a.cmd == "list":
        show_table(approvals.list_requests(a.incident, a.status))
    elif a.cmd == "show":
        print(json.dumps(approvals.get(a.id), indent=2))
    elif a.cmd in ("approve", "reject"):
        r = approvals.decide(a.id, a.by, a.cmd == "approve", a.comment)
        show_table([r])
    elif a.cmd == "approve-all":
        for r in approvals.list_requests(a.incident, "pending"):
            show_table([approvals.decide(r["id"], a.by, True, a.comment)])
    elif a.cmd == "execute":
        for res in executor.run(a.incident):
            print(json.dumps(res))
        show_table(approvals.list_requests(a.incident))
    elif a.cmd == "audit":
        for e in audit.read(a.incident):
            print(json.dumps(e))
    elif a.cmd == "kill-switch":
        if a.state == "on":
            killswitch.engage(a.by, a.reason)
        elif a.state == "off":
            killswitch.release(a.by)
        print("KILL SWITCH ENGAGED - no actions will run" if killswitch.engaged() else "kill switch off")


if __name__ == "__main__":
    main()
