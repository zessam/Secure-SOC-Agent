"""Deterministic policy review of the planner's proposals (plain code, not AI).

The model proposes; this code decides what may go to the human approval queue:
- requires_approval is set from a fixed table, never by the model
- blocked: Tier 0 targets, out-of-scope targets, protected domains/IPs, signed-binary hashes,
  blast radius > MAX_USERS, actions without evidence
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

ASSETS_FILE = Path(__file__).resolve().parents[2] / "data" / "environment" / "assets.json"

MAX_USERS = 10

# Low-impact actions that may run without a human (still logged).
NO_APPROVAL = {"run_av_scan", "contact_user", "escalate", "close_case"}

HOST_ACTIONS = {"isolate_host", "kill_process", "quarantine_file", "run_av_scan"}
USER_ACTIONS = {"reset_password", "revoke_sessions", "disable_user", "remove_inbox_rule", "clear_ad_description"}
IOC_ACTIONS = {"block_ip", "block_domain", "block_hash"}
NEEDS_EVIDENCE = HOST_ACTIONS | USER_ACTIONS | IOC_ACTIONS | {
    "block_sender_domain", "purge_email", "remove_group_member", "disable_legacy_auth"}

PROTECTED_DOMAINS = ("contoso.com", "contoso.local", "contoso.sharepoint.com", "microsoft.com",
                     "microsoftonline.com", "office.com", "office365.com", "windowsupdate.com", "live.com")
PROTECTED_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                         "198.51.100.0/24")]  # internal + corporate egress
BROAD_TARGETS = ("all", "all-staff", "all staff", "everyone", "*", "domain users")


def _load_tiers() -> dict[str, str]:
    try:
        return {a["hostname"].upper(): a["tier"] for a in json.loads(ASSETS_FILE.read_text(encoding="utf-8"))}
    except (OSError, ValueError):
        return {}


def _norm(value: str) -> str:
    return value.strip().lower()


def _is_protected_domain(domain: str) -> bool:
    d = _norm(domain).rstrip(".")
    return any(d == p or d.endswith("." + p) for p in PROTECTED_DOMAINS)


def _is_protected_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(ip in net for net in PROTECTED_NETWORKS)


def review_plan(plan: dict, investigation: dict | None, signed_hashes: set[str] | None = None) -> dict:
    """Return a copy of the plan where every action has requires_approval, policy and policy_reason."""
    investigation = investigation or {}
    signed_hashes = {h.lower() for h in (signed_hashes or set())}
    tiers = _load_tiers()
    scope = investigation.get("scope") or {}
    compromised_hosts = {_norm(h) for h in scope.get("compromised_hosts", [])}
    compromised_users = {_norm(u) for u in scope.get("compromised_users", [])}
    clean = {_norm(x) for x in scope.get("checked_and_clean", [])}
    iocs = {_norm(i.get("value", "")) for i in investigation.get("indicators", []) if isinstance(i, dict)}

    actions: list[dict[str, Any]] = [dict(a) for a in plan.get("actions", [])]
    user_targets = {_norm(a["target"]) for a in actions if a.get("action") in USER_ACTIONS}

    for a in actions:
        act, target = a.get("action", ""), str(a.get("target", ""))
        t = _norm(target)
        a["requires_approval"] = act not in NO_APPROVAL
        reason = None

        if act in NEEDS_EVIDENCE and not a.get("evidence_event_ids"):
            reason = "no evidence cited"
        elif t in BROAD_TARGETS and act != "purge_email":
            reason = "target is a whole group / all users: blast radius too large"
        elif act in HOST_ACTIONS - {"run_av_scan"} and tiers.get(target.upper()) == "tier0":
            reason = f"{target} is a Tier 0 system: containment is an Incident Response decision, escalate instead"
        elif act == "disable_user" and t in {"administrator", "krbtgt"}:
            reason = "built-in critical account"
        elif act in HOST_ACTIONS - {"run_av_scan"} and t in clean:
            reason = "host was checked and found clean by the investigation (over-containment)"
        elif act in HOST_ACTIONS - {"run_av_scan"} and compromised_hosts and t not in compromised_hosts:
            reason = "host is not in the investigation's compromised scope"
        elif act in USER_ACTIONS and len(user_targets) > MAX_USERS:
            reason = f"plan touches {len(user_targets)} accounts (max {MAX_USERS}): escalate instead"
        elif act in USER_ACTIONS and t in clean:
            reason = "account was checked and found clean by the investigation"
        elif act in ("block_domain", "block_sender_domain") and _is_protected_domain(t):
            reason = "corporate / Microsoft domain must never be blocked"
        elif act == "block_ip" and _is_protected_ip(t):
            reason = "internal or corporate IP must never be blocked"
        elif act == "block_hash" and t in signed_hashes:
            reason = "hash of a signed, trusted binary: blocking it would break every machine"
        elif act in IOC_ACTIONS and iocs and t not in iocs:
            reason = "indicator is not among the investigation's confirmed IOCs"

        a["policy"] = "blocked" if reason else "allowed"
        a["policy_reason"] = reason or ("needs human approval" if a["requires_approval"] else "low impact, auto-allowed")

    # Critical or escalated incidents must always reach Incident Response.
    if (investigation.get("escalate_to_human") or investigation.get("severity") == "critical") and \
            not any(a.get("action") == "escalate" for a in actions):
        actions.append({"action": "escalate", "target": "Incident Response", "urgency": "immediate",
                        "reason": "added by policy: critical or escalated incident", "evidence_event_ids": [],
                        "requires_approval": False, "policy": "allowed", "policy_reason": "added by policy"})

    reviewed = dict(plan)
    reviewed["actions"] = actions
    reviewed["policy_summary"] = {
        "allowed_needing_approval": sum(a["policy"] == "allowed" and a["requires_approval"] for a in actions),
        "allowed_auto": sum(a["policy"] == "allowed" and not a["requires_approval"] for a in actions),
        "blocked": sum(a["policy"] == "blocked" for a in actions),
    }
    return reviewed
