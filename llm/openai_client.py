"""OpenAI provider — drop-in alternative to ``ClaudeClient``.

Same external interface (``client.message(...)`` returns ``LLMResponse``) so
the planner / synthesizer / triager are provider-agnostic. The
``LLMContext`` factory picks whichever provider has an API key set.

Notes vs ClaudeClient:
  - Caching: OpenAI auto-caches identical prompt prefixes >= 1024 tokens.
    No explicit ``cache_control`` marker is needed. We still keep the
    profile data in the user turn so the system-prompt prefix is stable.
  - Tool use: OpenAI calls it "function calling". We translate Anthropic-
    style tool specs (``input_schema``) to OpenAI's ``parameters`` shape
    on the fly so planner/synth/triage code doesn't have to change.
"""

from __future__ import annotations

import logging
from typing import Any

from config.settings import (
    LLM_MODEL_PAYLOAD,
    LLM_MODEL_PLANNER,
    LLM_MODEL_TRIAGE,
)
from llm.client import (
    LLMResponse,
    LLMUnavailableError,
    LLMUsage,
    assert_no_profile_leak,
)

logger = logging.getLogger(__name__)


def _to_openai_tool(spec: dict[str, Any]) -> dict[str, Any]:
    """Anthropic-style {name, description, input_schema} -> OpenAI {type, function}."""
    return {
        "type": "function",
        "function": {
            "name": spec["name"],
            "description": spec.get("description", ""),
            "parameters": spec.get("input_schema", {"type": "object"}),
        },
    }


class OpenAIClient:
    """OpenAI wrapper with the same ``message()`` contract as ClaudeClient."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        validate_models: bool = False,
    ) -> None:
        try:
            import openai  # type: ignore[import-not-found]
        except ImportError as e:
            raise LLMUnavailableError(
                "openai SDK not installed. `pip install openai` to enable the OpenAI provider."
            ) from e

        import os
        resolved = api_key or os.environ.get("OPENAI_API_KEY")
        if not resolved:
            raise LLMUnavailableError(
                "OPENAI_API_KEY not set. Export the env var to use the OpenAI provider."
            )

        self._openai = openai
        self._client = openai.OpenAI(api_key=resolved)
        self._validated = False
        if validate_models:
            self._validate_models()

    def _validate_models(self) -> None:
        if self._validated:
            return
        wanted = {LLM_MODEL_PLANNER, LLM_MODEL_PAYLOAD, LLM_MODEL_TRIAGE}
        try:
            available = {m.id for m in self._client.models.list().data}
        except Exception as e:
            logger.warning("could not list OpenAI models for validation: %s", e)
            return
        missing = wanted - available
        if missing:
            raise LLMUnavailableError(
                f"configured model IDs not found on OpenAI API: {sorted(missing)}. "
                f"Set ASI_LLM_MODEL_PLANNER / _PAYLOAD / _TRIAGE in env to OpenAI model names "
                f"(e.g. gpt-4o, gpt-4o-mini)."
            )
        self._validated = True

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

        # Build messages — system + user only (single turn).
        if isinstance(user, str):
            user_text = user
        else:
            # Flatten Anthropic-style content blocks into a single string.
            user_text = "".join(
                b.get("text", "") if isinstance(b, dict) else str(b) for b in user
            )

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_text},
        ]

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = [_to_openai_tool(t) for t in tools]
            # When a single tool is offered, force the model to call it.
            if len(tools) == 1:
                kwargs["tool_choice"] = {
                    "type": "function",
                    "function": {"name": tools[0]["name"]},
                }
            else:
                kwargs["tool_choice"] = "auto"

        resp = self._client.chat.completions.create(**kwargs)

        choice = resp.choices[0] if resp.choices else None
        text = ""
        tool_uses: list[dict[str, Any]] = []
        stop_reason = ""
        if choice is not None:
            msg = choice.message
            text = msg.content or ""
            stop_reason = choice.finish_reason or ""
            for tc in (msg.tool_calls or []):
                # OpenAI returns arguments as a JSON string — parse to dict.
                import json
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except (json.JSONDecodeError, TypeError):
                    args = {"_raw_arguments": tc.function.arguments}
                tool_uses.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": args,
                })

        usage_obj = getattr(resp, "usage", None)
        cache_read = 0
        if usage_obj is not None:
            # New OpenAI API (Aug 2024+) reports cached tokens here.
            details = getattr(usage_obj, "prompt_tokens_details", None)
            if details is not None:
                cache_read = getattr(details, "cached_tokens", 0) or 0
        usage = LLMUsage(
            input_tokens=getattr(usage_obj, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage_obj, "completion_tokens", 0) or 0,
            cache_creation_input_tokens=0,  # OpenAI doesn't expose this separately
            cache_read_input_tokens=cache_read,
        )

        return LLMResponse(
            text=text,
            tool_uses=tool_uses,
            stop_reason=stop_reason,
            usage=usage,
            model=getattr(resp, "model", model),
        )
