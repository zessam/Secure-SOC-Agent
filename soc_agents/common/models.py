"""Model selection: Gemini (Google AI Studio) or a local vLLM server.

SOC_MODEL_PROVIDER=vllm (default, local server) or gemini. Each agent asks for a tier (pro / flash / lite);
model names come from env vars so nothing is hard-coded in agent code.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
from typing import Any, AsyncGenerator

import httpx

from google.adk.models._capabilities import LlmCapabilities
from google.adk.models.apigee_llm import CompletionsHTTPClient
from google.adk.models.base_llm import BaseLlm
from google.adk.models.google_llm import Gemini
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import PrivateAttr

GEMINI_DEFAULTS = {"pro": "gemini-3.1-pro-preview", "flash": "gemini-3.5-flash", "lite": "gemini-3.5-flash-lite"}


class _VllmClient(CompletionsHTTPClient):
    """ADK's OpenAI-compatible client, keeping the full model name (e.g. Qwen/Qwen3-32B)."""

    def __init__(self, model: str, **kwargs: Any):
        super().__init__(**kwargs)
        self._model = model

    def _construct_payload(self, llm_request: LlmRequest, stream: bool) -> dict[str, Any]:
        payload = super()._construct_payload(llm_request, stream)
        payload["model"] = self._model
        if os.environ.get("VLLM_THINKING", "off").lower() in ("off", "false", "0"):
            # Qwen-style models: skip the hidden reasoning tokens (much faster / cheaper per call).
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        fmt = payload.get("response_format")
        if fmt and fmt.get("type") == "json_schema" and "schema" not in fmt["json_schema"]:
            fmt["json_schema"] = {"name": "output", "schema": fmt["json_schema"]}
        return payload


log = logging.getLogger(__name__)

# One local GPU server: cap simultaneous requests (the 4 parallel specialists otherwise time out).
_SLOTS: dict[int, asyncio.Semaphore] = {}


def _slots() -> asyncio.Semaphore:
    loop_id = id(asyncio.get_running_loop())
    if loop_id not in _SLOTS:
        _SLOTS[loop_id] = asyncio.Semaphore(int(os.environ.get("VLLM_MAX_CONCURRENCY", "2")))
    return _SLOTS[loop_id]
_RETRIES = 4


def _retriable(e: BaseException) -> bool:
    if isinstance(e, (httpx.TimeoutException, httpx.NetworkError)):
        return True
    return isinstance(e, httpx.HTTPStatusError) and e.response.status_code in (408, 429, 500, 502, 503, 504)


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
        for attempt in range(_RETRIES + 1):
            try:
                async with _slots():
                    responses = [r async for r in self._client.generate_content_async(llm_request, False)]
                break
            except Exception as e:  # noqa: BLE001
                if attempt == _RETRIES or not _retriable(e):
                    raise
                delay = min(60, 5 * 2 ** attempt) + random.uniform(0, 2)
                log.warning("vLLM call failed (%s); retry %d/%d in %.0fs", type(e).__name__, attempt + 1, _RETRIES, delay)
                await asyncio.sleep(delay)
        for response in responses:
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
        # Free tier allows ~5 requests/min per model: wait and retry on 429/503 instead of failing.
        retry = types.HttpRetryOptions(attempts=8, initial_delay=15, max_delay=65, exp_base=1.5,
                                       http_status_codes=[429, 500, 503])
        return Gemini(model=os.environ.get(f"GEMINI_MODEL_{tier.upper()}", GEMINI_DEFAULTS[tier]),
                      retry_options=retry)
    raise RuntimeError(f"Unknown SOC_MODEL_PROVIDER {provider!r} (use gemini or vllm)")
