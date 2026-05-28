"""Thin Claude wrapper with the v3 prompt-cache contract.

PROMPT-CACHE CONTRACT (do not break — tests/test_llm_client.py asserts this):

  System prompt contains ONLY static, cacheable material:
    - role / persona
    - the full ASI taxonomy (large, reused on every call)
    - the JSON output schema
    - general adversarial-reasoning guardrails

  Per-target data (AgentProfile, payload seeds, finding details) goes in
  the USER turn so cache hits land. Putting profile data into the system
  prompt silently destroys cache hit rate; the contract test guards this.

Caching uses Anthropic's `cache_control = {"type": "ephemeral"}` marker on
the last static content block of the system prompt. Cache TTL is ~5 min;
sequential planner / synthesizer / triager calls within a single scan
benefit. The `usage.cache_read_input_tokens` field on every response
records whether the cache was used.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from config.settings import (
    ANTHROPIC_API_KEY,
    LLM_MODEL_PAYLOAD,
    LLM_MODEL_PLANNER,
    LLM_MODEL_TRIAGE,
)

logger = logging.getLogger(__name__)


class LLMUnavailableError(RuntimeError):
    """Raised when the LLM layer is requested but the SDK or API key is missing."""


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    @classmethod
    def from_anthropic(cls, usage: Any) -> "LLMUsage":
        return cls(
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        )


@dataclass
class LLMResponse:
    text: str
    tool_uses: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    usage: LLMUsage = field(default_factory=LLMUsage)
    model: str = ""


def _build_cached_system(system_text: str) -> list[dict[str, Any]]:
    """Format the system prompt as cache-enabled content blocks.

    Single block, marked ``ephemeral`` so the static taxonomy + schema is
    re-used across the planner/synthesizer/triager calls in one scan.
    """
    return [
        {
            "type": "text",
            "text": system_text,
            "cache_control": {"type": "ephemeral"},
        }
    ]


# --- contract enforcement (used by tests/test_llm_client.py) --------------

# Substrings that MUST NEVER appear in any system prompt we send. If they
# do, per-target data has leaked out of the user turn and cache hit rate
# will silently collapse.
PROFILE_LEAK_MARKERS: tuple[str, ...] = (
    '"base_url"',
    '"agent_id"',
    '"endpoints"',
    '"inferred_capabilities"',
    '"tools"',
    '"schema_version"',
    "AgentProfile(",
)


def assert_no_profile_leak(system_text: str) -> None:
    """Raise if the system prompt contains anything that looks like
    serialized profile data. Used by client + tests."""
    for marker in PROFILE_LEAK_MARKERS:
        if marker in system_text:
            raise AssertionError(
                f"prompt-cache contract violation: system prompt contains {marker!r}; "
                f"profile/target data must live in the user turn"
            )


class ClaudeClient:
    """Thin wrapper around ``anthropic.Anthropic`` with the cache contract."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        validate_models: bool = False,
    ) -> None:
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as e:
            raise LLMUnavailableError(
                "anthropic SDK not installed. `pip install anthropic` to enable --llm."
            ) from e

        resolved = api_key or ANTHROPIC_API_KEY
        if not resolved:
            raise LLMUnavailableError(
                "ANTHROPIC_API_KEY not set. Export the env var to enable --llm."
            )

        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=resolved)
        self._validated = False
        if validate_models:
            self._validate_models()

    # ---- model-ID startup validation ---------------------------------

    def _validate_models(self) -> None:
        """Confirm the configured model IDs actually exist on the API.

        Fails fast with a clear error rather than letting the first scan
        crash mid-flight on a model 404.
        """
        if self._validated:
            return
        wanted = {LLM_MODEL_PLANNER, LLM_MODEL_PAYLOAD, LLM_MODEL_TRIAGE}
        try:
            available = {m.id for m in self._client.models.list().data}
        except Exception as e:
            logger.warning("could not list models for validation: %s", e)
            return
        missing = wanted - available
        if missing:
            raise LLMUnavailableError(
                f"configured model IDs not found on API: {sorted(missing)}. "
                f"Check ASI_LLM_MODEL_PLANNER / _PAYLOAD / _TRIAGE in env."
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
        """Send a single message. ``system`` is cache-marked automatically.

        ``user`` may be a plain string or a list of content blocks (for
        complex tool-result follow-ups).
        """
        assert_no_profile_leak(system)

        system_blocks = _build_cached_system(system)
        user_content: list[dict[str, Any]]
        if isinstance(user, str):
            user_content = [{"type": "text", "text": user}]
        else:
            user_content = user

        kwargs: dict[str, Any] = {
            "model": model,
            "system": system_blocks,
            "messages": [{"role": "user", "content": user_content}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools

        resp = self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        tool_uses: list[dict[str, Any]] = []
        for block in getattr(resp, "content", []) or []:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", "") or "")
            elif btype == "tool_use":
                tool_uses.append({
                    "id": getattr(block, "id", ""),
                    "name": getattr(block, "name", ""),
                    "input": getattr(block, "input", {}) or {},
                })

        return LLMResponse(
            text="".join(text_parts),
            tool_uses=tool_uses,
            stop_reason=getattr(resp, "stop_reason", "") or "",
            usage=LLMUsage.from_anthropic(getattr(resp, "usage", None)),
            model=getattr(resp, "model", model),
        )
