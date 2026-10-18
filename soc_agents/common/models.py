"""Model selection: Gemini (Google AI Studio) or a local vLLM server.

SOC_MODEL_PROVIDER=vllm (default, local server) or gemini. Each agent asks for a tier (pro / flash / lite);
model names come from env vars so nothing is hard-coded in agent code.
"""
from __future__ import annotations

import os
from typing import Any, AsyncGenerator

from google.adk.models._capabilities import LlmCapabilities
from google.adk.models.apigee_llm import CompletionsHTTPClient
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from pydantic import PrivateAttr

GEMINI_DEFAULTS = {"pro": "gemini-3.1-pro-preview", "flash": "gemini-3.5-flash", "lite": "gemini-3.5-flash"}


class _VllmClient(CompletionsHTTPClient):
    """ADK's OpenAI-compatible client, keeping the full model name (e.g. Qwen/Qwen3-32B)."""

    def __init__(self, model: str, **kwargs: Any):
        super().__init__(**kwargs)
        self._model = model

    def _construct_payload(self, llm_request: LlmRequest, stream: bool) -> dict[str, Any]:
        payload = super()._construct_payload(llm_request, stream)
        payload["model"] = self._model
        fmt = payload.get("response_format")
        if fmt and fmt.get("type") == "json_schema" and "schema" not in fmt["json_schema"]:
            fmt["json_schema"] = {"name": "output", "schema": fmt["json_schema"]}
        return payload


class VllmLlm(BaseLlm):
    """Any OpenAI-compatible server (vLLM). Start vLLM with --enable-auto-tool-choice --tool-call-parser <x>."""

    base_url: str
    api_key: str | None = None
    _client: _VllmClient | None = PrivateAttr(default=None)

    @property
    def capabilities(self) -> LlmCapabilities:
        # ADK then enforces output_schema through a set_model_response tool call.
        return LlmCapabilities(output_schema_and_tools=False)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        if self._client is None:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            self._client = _VllmClient(self.model, base_url=self.base_url, headers=headers)
        async for response in self._client.generate_content_async(llm_request, stream):
            yield response


def get_model(tier: str) -> str | BaseLlm:
    """Model for a tier: 'pro' (reasoning), 'flash' (specialists), 'lite' (guard/judge)."""
    provider = os.environ.get("SOC_MODEL_PROVIDER", "vllm").lower()
    if provider == "vllm":
        model = os.environ.get(f"VLLM_MODEL_{tier.upper()}") or os.environ.get("VLLM_MODEL")
        if not model:
            raise RuntimeError("Set VLLM_MODEL (the name shown by GET <VLLM_BASE_URL>/models)")
        return VllmLlm(model=model, base_url=os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1"),
                       api_key=os.environ.get("VLLM_API_KEY"))
    if provider == "gemini":
        return os.environ.get(f"GEMINI_MODEL_{tier.upper()}", GEMINI_DEFAULTS[tier])
    raise RuntimeError(f"Unknown SOC_MODEL_PROVIDER {provider!r} (use gemini or vllm)")
