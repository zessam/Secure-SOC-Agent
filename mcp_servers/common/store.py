"""Loads one scenario pack (plus the shared environment) as the mock systems' backing data.

Only the system files listed in SYSTEM_FILES are read. expected.yaml (ground truth) and
scenario.yaml (narrative / timeline) are never opened here, so no MCP tool can leak them.
"""
from __future__ import annotations

import json
import os
from contextvars import ContextVar
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
        # SCENARIO=ALL loads every scenario at once (one busy SOC day); otherwise one scenario folder.
        self.folders = self._resolve_folders(self.scenario_id)
        self.files_read: list[str] = []

        self.alerts: list[dict] = []
        self.siem_events: list[dict] = []
        self.edr_events: list[dict] = []
        self.ad_objects: dict = {"overrides": {}}
        self.soar_cases: list[dict] = []
        self.tickets: list[dict] = []
        intel: dict[str, dict] = {}
        for folder in self.folders:
            self.alerts += self._json(folder, "alerts.json", [])
            self.siem_events += self._jsonl(folder, "siem_events.jsonl")
            self.edr_events += self._jsonl(folder, "edr_telemetry.jsonl")
            self.ad_objects["overrides"].update(self._json(folder, "ad_objects.json", {}).get("overrides") or {})
            for ind in self._json(folder, "ti_indicators.json", []):
                intel[ind["indicator"].lower()] = ind
            case = self._json(folder, "soar_case.json", None)
            if case:
                self.soar_cases.append(case)
            self.tickets += self._json(folder, "tickets.json", [])
        self.ti_indicators: list[dict] = list(intel.values())

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
        self._cache: dict[str, Any] = {}

    def cached(self, key: str, build) -> Any:
        """Per-scenario memo for derived views (e.g. merged AD users)."""
        if key not in self._cache:
            self._cache[key] = build()
        return self._cache[key]

    # ---- loading -------------------------------------------------------------------------
    def _resolve_folders(self, scenario_id: str) -> list[Path]:
        catalog = json.loads((self.data_dir / "scenarios" / "catalog.json").read_text(encoding="utf-8"))
        if scenario_id == "ALL":
            return [self.data_dir / e["folder"] for e in catalog["scenarios"]]
        for entry in catalog["scenarios"]:
            if entry["id"].upper() == scenario_id:
                return [self.data_dir / entry["folder"]]
        known = ", ".join(e["id"] for e in catalog["scenarios"])
        raise ValueError(f"Unknown scenario {scenario_id!r}. Known: ALL, {known}")

    def _path(self, folder: Path, name: str) -> Path:
        if name not in SYSTEM_FILES:
            raise PermissionError(f"{name} is not a system file and must not be loaded")
        return folder / name

    def _json(self, folder: Path, name: str, default: Any) -> Any:
        path = self._path(folder, name)
        if not path.exists():
            return default
        self.files_read.append(str(path))
        return json.loads(path.read_text(encoding="utf-8"))

    def _jsonl(self, folder: Path, name: str) -> list[dict]:
        path = self._path(folder, name)
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


# The scenario of the current tool call (set per call by the read_tool wrapper).
active_scenario: ContextVar[str | None] = ContextVar("soc_active_scenario", default=None)


class MultiStore:
    """Serves every scenario from one server, each kept separate; the scenario is chosen per tool call.

    Scenarios load lazily on first use, so a server only reads the data it is asked about.
    """

    def __init__(self, default: str | None = None, data_dir: str | Path | None = None):
        self.data_dir = data_dir
        self.default = (default or "").upper() or None
        self._stores: dict[str, ScenarioStore] = {}

    def store(self, scenario_id: str | None = None) -> ScenarioStore:
        sid = (scenario_id or active_scenario.get() or self.default or "").upper()
        if not sid:
            raise ValueError("No scenario for this call: start from an alert id such as ALR-A2-001")
        if sid not in self._stores:
            self._stores[sid] = ScenarioStore(sid, self.data_dir)
        return self._stores[sid]

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store(), name)
