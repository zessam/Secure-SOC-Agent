"""Building blocks shared by agent output schemas."""
from __future__ import annotations

import json
from typing import Any, Literal, get_origin

from pydantic import BaseModel, Field, model_validator


class AgentOutput(BaseModel):
    """Base for agent outputs. Some local models (e.g. Qwen on vLLM) send nested objects or lists
    as JSON strings; decode those before validation instead of failing the whole answer."""

    @model_validator(mode="before")
    @classmethod
    def _decode_json_strings(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        for key, value in data.items():
            if not isinstance(value, str):
                continue
            if value.strip()[:1] in ("{", "["):
                try:
                    data[key] = json.loads(value)
                    continue
                except ValueError:
                    pass
            field = cls.model_fields.get(key)
            if field is not None and get_origin(field.annotation) is list:
                # A list sent as plain or broken text: keep the content instead of failing the answer.
                data[key] = [value.strip().strip("[]").strip()] if value.strip() else []
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
    statement: str = Field(description="One fact, max 20 words")
    evidence_event_ids: list[str] = Field(description="1-3 event ids that prove it")
    confidence: Literal["low", "medium", "high"]


class Indicator(BaseModel):
    value: str
    type: Literal["ip", "domain", "url", "sha256", "md5", "email", "file_name", "registry", "account"]
    why: str = Field(description="Max 6 words, e.g. 'C2 domain'")
