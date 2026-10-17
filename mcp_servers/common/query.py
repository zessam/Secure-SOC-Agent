"""Filtering, paging and aggregation shared by the mock servers.

Every search returns at most MAX_LIMIT events plus the total match count, so an agent has to
narrow its filters (user / host / time window) instead of reading whole datasets.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Callable, Iterable

from .store import parse_ts

MAX_LIMIT = 50
DEFAULT_LIMIT = 25

# Fields an "entity" filter matches against (user, host or IP / domain / mailbox).
ENTITY_FIELDS = (
    "user.name", "user.email", "user.target", "host.name", "host.ip",
    "source.ip", "destination.ip", "destination.domain", "url.domain",
    "dns.question.name", "email.from", "email.to", "azure.device",
)


def get_field(event: dict, dotted: str) -> Any:
    cur: Any = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _values(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, list):
        for v in value:
            yield from _values(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _values(v)
    else:
        yield str(value)


def _eq(value: Any, wanted: str) -> bool:
    w = wanted.lower()
    return any(v.lower() == w for v in _values(value))


def contains_value(event: dict, needle: str) -> bool:
    """True when any field value equals needle (case-insensitive), e.g. an IOC anywhere in an event."""
    return _eq(public(event), needle)


def public(event: dict) -> dict:
    return {k: v for k, v in event.items() if not k.startswith("_")}


def clamp_limit(limit: int | None) -> int:
    if not limit or limit < 1:
        return DEFAULT_LIMIT
    return min(int(limit), MAX_LIMIT)


def build_filter(
    *,
    entity: str | None = None,
    user: str | None = None,
    host: str | None = None,
    ip: str | None = None,
    dataset: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    text: str | None = None,
    start: str | None = None,
    end: str | None = None,
) -> Callable[[dict], bool]:
    start_dt = parse_ts(start) if start else None
    end_dt = parse_ts(end) if end else None
    text_l = text.lower() if text else None

    def match(ev: dict) -> bool:
        if start_dt and ev["_ts"] < start_dt:
            return False
        if end_dt and ev["_ts"] > end_dt:
            return False
        if dataset and not str(get_field(ev, "event.dataset") or "").lower().startswith(dataset.lower()):
            return False
        if action and not _eq(get_field(ev, "event.action"), action):
            return False
        if outcome and not _eq(get_field(ev, "event.outcome"), outcome):
            return False
        if user and not (_eq(get_field(ev, "user.name"), user) or _eq(get_field(ev, "user.target"), user)
                         or _eq(get_field(ev, "user.email"), user)):
            return False
        if host and not (_eq(get_field(ev, "host.name"), host) or _eq(get_field(ev, "azure.device"), host)):
            return False
        if ip and not any(_eq(get_field(ev, f), ip) for f in ("source.ip", "destination.ip", "host.ip")):
            return False
        if entity and not any(_eq(get_field(ev, f), entity) for f in ENTITY_FIELDS):
            return False
        if text_l and text_l not in json.dumps(public(ev)).lower():
            return False
        return True

    return match


def page(events: list[dict], limit: int | None, order: str = "asc") -> dict:
    lim = clamp_limit(limit)
    ordered = events if order == "asc" else list(reversed(events))
    out = ordered[:lim]
    return {
        "total_matched": len(events),
        "returned": len(out),
        "truncated": len(events) > len(out),
        "hint": "Narrow the time window or add filters to see the rest." if len(events) > len(out) else None,
        "events": [public(e) for e in out],
    }


def aggregate(events: list[dict], group_by: str, top: int = 20) -> dict:
    counts = Counter()
    first: dict[str, str] = {}
    last: dict[str, str] = {}
    for ev in events:
        vals = list(_values(get_field(ev, group_by))) or ["(none)"]
        for v in vals:
            counts[v] += 1
            first.setdefault(v, ev["@timestamp"])
            last[v] = ev["@timestamp"]
    top = max(1, min(int(top or 20), MAX_LIMIT))
    return {
        "group_by": group_by,
        "total_events": len(events),
        "distinct_values": len(counts),
        "buckets": [
            {"value": v, "count": c, "first_seen": first[v], "last_seen": last[v]}
            for v, c in counts.most_common(top)
        ],
    }
