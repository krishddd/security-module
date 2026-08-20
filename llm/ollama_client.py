"""Ollama provider — local / air-gapped LLM backend.

Same external interface as ``ClaudeClient`` / ``OpenAIClient``
(``client.message(...) -> LLMResponse``) so the planner / synthesizer /
triager are provider-agnostic. Talks to a local Ollama server over plain HTTP
(default ``http://localhost:11434``) with NO API key — the point is running the
scanner fully offline against models on the operator's own hardware
(SOC2 / financial / defence deployments where cloud APIs are disallowed).

Wire protocol: Ollama's native ``POST /api/chat`` (non-streaming). Tools use
the OpenAI-compatible ``{type, function}`` shape (Ollama accepts it), so we
reuse the same tool translation. Unlike OpenAI, Ollama returns tool-call
arguments as an already-parsed object, not a JSON string.

Notes vs the cloud clients:
  - No prompt caching signal is exposed by Ollama, so cache usage stays 0.
  - No forced tool_choice: Ollama decides whether to call an offered tool.
  - Uses httpx (a core dependency) — no extra SDK, so it installs in an
    air-gapped environment with just the core requirements.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from config.settings import (
    OLLAMA_BASE_URL,
    OLLAMA_MODEL_PAYLOAD,
    OLLAMA_MODEL_PLANNER,
    OLLAMA_MODEL_TRIAGE,
)
from llm.client import LLMResponse, LLMUnavailableError, LLMUsage, assert_no_profile_leak
from llm.openai_client import _to_openai_tool

logger = logging.getLogger(__name__)


class OllamaClient:
    """Local Ollama wrapper with the same ``message()`` contract as the cloud clients."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_s: float = 120.0,
        validate_models: bool = False,
    ) -> None:
        self._base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self._timeout_s = timeout_s
        self._client = httpx.Client(base_url=self._base_url, timeout=timeout_s)
        self._validated = False
        if validate_models:
            self._validate_models()

    # ---- model presence check -----------------------------------------

    def _installed_models(self) -> set[str]:
        """Model names currently pulled into the local Ollama server."""
        try:
            resp = self._client.get("/api/tags")
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise LLMUnavailableError(
                f"could not reach Ollama at {self._base_url} (/api/tags): {e}. "
                f"Is `ollama serve` running? Set ASI_OLLAMA_BASE_URL to point elsewhere."
            ) from e
        names: set[str] = set()
        for m in data.get("models", []) or []:
            name = m.get("name") or m.get("model") or ""
            if name:
                names.add(name)
                # Ollama tags models as "llama3.1:latest"; also expose the bare name.
                names.add(name.split(":", 1)[0])
        return names

    def _validate_models(self) -> None:
        if self._validated:
            return
        wanted = {OLLAMA_MODEL_PLANNER, OLLAMA_MODEL_PAYLOAD, OLLAMA_MODEL_TRIAGE}
        installed = self._installed_models()
        missing = {w for w in wanted if w not in installed and w.split(":", 1)[0] not in installed}
        if missing:
            raise LLMUnavailableError(
                f"Ollama models not pulled locally: {sorted(missing)}. "
                f"Run `ollama pull <model>` or set ASI_OLLAMA_MODEL_PLANNER / "
                f"_PAYLOAD / _TRIAGE to installed model names."
            )
        self._validated = True

    # ---- core message call --------------------------------------------

    def message(
        self,
        *,
        model: str,
        system: str,
        user: str | list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """Same signature as ClaudeClient.message. Profile-leak check fires here too."""
        assert_no_profile_leak(system)

        if isinstance(user, str):
            user_text = user
        else:
            user_text = "".join(
                b.get("text", "") if isinstance(b, dict) else str(b) for b in user
            )

        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_text},
            ],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = [_to_openai_tool(t) for t in tools]

        try:
            resp = self._client.post("/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as e:
            raise LLMUnavailableError(
                f"Ollama request to {self._base_url}/api/chat failed: {e}"
            ) from e

        msg = data.get("message", {}) if isinstance(data, dict) else {}
        text = msg.get("content", "") or ""

        tool_uses: list[dict[str, Any]] = []
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            args = fn.get("arguments", {})
            # Ollama returns arguments as an object; tolerate a JSON string too.
            if isinstance(args, str):
                import json
                try:
                    args = json.loads(args or "{}")
                except (json.JSONDecodeError, TypeError):
                    args = {"_raw_arguments": args}
            tool_uses.append({
                "id": tc.get("id", "") if isinstance(tc, dict) else "",
                "name": fn.get("name", ""),
                "input": args if isinstance(args, dict) else {"_value": args},
            })

        # Ollama reports token counts as prompt_eval_count / eval_count.
        usage = LLMUsage(
            input_tokens=int(data.get("prompt_eval_count", 0) or 0),
            output_tokens=int(data.get("eval_count", 0) or 0),
        )
        # done_reason: "stop" | "length" | ... (present on newer Ollama); default "stop".
        stop_reason = data.get("done_reason") or ("stop" if data.get("done") else "")

        return LLMResponse(
            text=text,
            tool_uses=tool_uses,
            stop_reason=stop_reason,
            usage=usage,
            model=data.get("model", model),
        )
