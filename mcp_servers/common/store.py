"""Loads one scenario pack (plus the shared environment) as the mock systems' backing data.

Only the system files listed in SYSTEM_FILES are read. expected.yaml (ground truth) and
scenario.yaml (narrative / timeline) are never opened here, so no MCP tool can leak them.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

SYSTEM_FILES = (
    "alerts.json",
    "siem_events.jsonl",
    "edr_telemetry.jsonl",
    "ad_objects.json",
    "ti_indicators.json",
    "soar_case.json",
    "tickets.json",
)


def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp; a trailing Z is accepted and naive values are treated as UTC."""
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ScenarioStore:
    def __init__(self, scenario_id: str | None = None, data_dir: str | Path | None = None):
        self.data_dir = Path(data_dir or os.environ.get("SOC_DATA_DIR") or DEFAULT_DATA_DIR)
        self.scenario_id = (scenario_id or os.environ.get("SCENARIO") or "").upper()
        if not self.scenario_id:
            raise ValueError("No scenario selected: pass scenario_id or set SCENARIO (e.g. SCENARIO=A2)")
        self.folder = self._resolve_folder(self.scenario_id)
        self.files_read: list[str] = []

        self.alerts: list[dict] = self._json("alerts.json", [])
        self.siem_events: list[dict] = self._jsonl("siem_events.jsonl")
        self.edr_events: list[dict] = self._jsonl("edr_telemetry.jsonl")
        self.ad_objects: dict = self._json("ad_objects.json", {})
        self.ti_indicators: list[dict] = self._json("ti_indicators.json", [])
        self.soar_case: dict | None = self._json("soar_case.json", None)
        self.tickets: list[dict] = self._json("tickets.json", [])

        env = self.data_dir / "environment"
        self.ad_users: list[dict] = self._env_json(env / "ad_users.json", [])
        self.ad_groups: list[dict] = self._env_json(env / "ad_groups.json", [])
        self.assets: list[dict] = self._env_json(env / "assets.json", [])
        self.network: dict = self._env_json(env / "network.json", {})

        for ev in self.siem_events + self.edr_events:
            ev["_ts"] = parse_ts(ev["@timestamp"])
        self.siem_events.sort(key=lambda e: e["_ts"])
        self.edr_events.sort(key=lambda e: e["_ts"])
        self._by_id = {e["event"]["id"]: e for e in self.siem_events + self.edr_events}

    # ---- loading -------------------------------------------------------------------------
    def _resolve_folder(self, scenario_id: str) -> Path:
        catalog = json.loads((self.data_dir / "scenarios" / "catalog.json").read_text(encoding="utf-8"))
        for entry in catalog["scenarios"]:
            if entry["id"].upper() == scenario_id:
                return self.data_dir / entry["folder"]
        known = ", ".join(e["id"] for e in catalog["scenarios"])
        raise ValueError(f"Unknown scenario {scenario_id!r}. Known: {known}")

    def _path(self, name: str) -> Path:
        if name not in SYSTEM_FILES:
            raise PermissionError(f"{name} is not a system file and must not be loaded")
        return self.folder / name

    def _json(self, name: str, default: Any) -> Any:
        path = self._path(name)
        if not path.exists():
            return default
        self.files_read.append(str(path))
        return json.loads(path.read_text(encoding="utf-8"))

    def _jsonl(self, name: str) -> list[dict]:
        path = self._path(name)
        if not path.exists():
            return []
        self.files_read.append(str(path))
        with path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def _env_json(self, path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        self.files_read.append(str(path))
        return json.loads(path.read_text(encoding="utf-8"))

    # ---- shared lookups ------------------------------------------------------------------
    def event_by_id(self, event_id: str) -> dict | None:
        return self._by_id.get(event_id)
