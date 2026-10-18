"""Building blocks shared by agent output schemas."""
from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class AgentOutput(BaseModel):
    """Base for agent outputs. Some local models (e.g. Qwen on vLLM) send nested objects or lists
    as JSON strings; decode those before validation instead of failing the whole answer."""

    @model_validator(mode="before")
    @classmethod
    def _decode_json_strings(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and value.strip()[:1] in ("{", "["):
                    try:
                        data[key] = json.loads(value)
                    except ValueError:
                        pass
        return data


class Entities(BaseModel):
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)


class TimeWindow(BaseModel):
    start: str = Field(description="ISO-8601 UTC start of the window to investigate")
    end: str = Field(description="ISO-8601 UTC end of the window to investigate")



class Finding(BaseModel):
    statement: str = Field(description="One fact you established, in plain words")
    evidence_event_ids: list[str] = Field(description="Event ids from tool results that prove it")
    confidence: Literal["low", "medium", "high"]


class Indicator(BaseModel):
    value: str
    type: Literal["ip", "domain", "url", "sha256", "md5", "email", "file_name", "registry", "account"]
    why: str = Field(description="Why it is suspicious, e.g. 'unsigned payload dropped by powershell'")
