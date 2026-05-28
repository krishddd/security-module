"""LLMContext — single object the runner threads through a scan.

Bundles the per-scan ``Budget`` with optional planner / synthesizer /
triager instances. Anything that wants to use the LLM layer during a scan
reaches into ``self.adapter`` (for IO) and ``ctx`` (for LLM) — same shape
whether or not ``--llm`` was passed; testers just check ``ctx.synthesizer
is not None``.
"""

from __future__ import annotations

from dataclasses import dataclass

import logging
import os
from typing import Any, Literal

from llm.budget import Budget
from llm.client import ClaudeClient, LLMUnavailableError
from llm.payload_synthesizer import LLMPayloadSynthesizer
from llm.planner import LLMTestPlanner
from llm.triage import LLMTriager

logger = logging.getLogger(__name__)

Provider = Literal["anthropic", "openai", "auto"]


@dataclass
class LLMContext:
    budget: Budget
    client: Any | None = None        # ClaudeClient or OpenAIClient
    provider: str = ""               # "anthropic" / "openai" / ""
    planner: LLMTestPlanner | None = None
    synthesizer: LLMPayloadSynthesizer | None = None
    triager: LLMTriager | None = None

    @classmethod
    def disabled(cls) -> "LLMContext":
        """A context with no LLM at all — testers see ``synthesizer is None`` and skip."""
        return cls(budget=Budget())

    @classmethod
    def enable(
        cls,
        *,
        max_calls: int | None = None,
        max_spend_usd: float | None = None,
        provider: Provider = "auto",
    ) -> "LLMContext":
        """Build a fully-wired context.

        Provider selection (``provider="auto"``):
          1. ``ANTHROPIC_API_KEY`` present  -> Anthropic
          2. else ``OPENAI_API_KEY`` present -> OpenAI
          3. else raise ``LLMUnavailableError``

        Force a specific provider with ``provider="anthropic"`` or ``"openai"``.

        Model selection follows the picked provider — Claude IDs for
        Anthropic, GPT IDs for OpenAI — so the planner/synthesizer/triager
        never get called with a model name the chosen provider can't
        resolve. Users can override per-component via ASI_OPENAI_MODEL_*
        / ASI_ANTHROPIC_MODEL_* env vars (see config/settings.py).
        """
        from config.settings import (
            ANTHROPIC_MODEL_PAYLOAD, ANTHROPIC_MODEL_PLANNER, ANTHROPIC_MODEL_TRIAGE,
            OPENAI_MODEL_PAYLOAD, OPENAI_MODEL_PLANNER, OPENAI_MODEL_TRIAGE,
        )

        client, picked = _make_client(provider)
        budget = Budget(max_calls=max_calls, max_spend_usd=max_spend_usd)
        logger.info("LLM provider: %s", picked)

        if picked == "openai":
            m_planner, m_payload, m_triage = OPENAI_MODEL_PLANNER, OPENAI_MODEL_PAYLOAD, OPENAI_MODEL_TRIAGE
        else:
            m_planner, m_payload, m_triage = ANTHROPIC_MODEL_PLANNER, ANTHROPIC_MODEL_PAYLOAD, ANTHROPIC_MODEL_TRIAGE

        logger.info("LLM models: planner=%s payload=%s triage=%s", m_planner, m_payload, m_triage)

        return cls(
            budget=budget,
            client=client,
            provider=picked,
            planner=LLMTestPlanner(client, budget=budget, model=m_planner),
            synthesizer=LLMPayloadSynthesizer(client, budget=budget, model=m_payload),
            triager=LLMTriager(client, budget=budget, model=m_triage),
        )


def _make_client(provider: Provider) -> tuple[Any, str]:
    if provider == "anthropic":
        return ClaudeClient(), "anthropic"
    if provider == "openai":
        from llm.openai_client import OpenAIClient
        return OpenAIClient(), "openai"

    # auto: prefer Anthropic when both keys are set (better tool-use fidelity
    # in our planner; the user can override by passing provider="openai").
    has_anthropic = _key_is_real(os.environ.get("ANTHROPIC_API_KEY"))
    has_openai = _key_is_real(os.environ.get("OPENAI_API_KEY"))

    if has_anthropic:
        return ClaudeClient(), "anthropic"
    if has_openai:
        from llm.openai_client import OpenAIClient
        return OpenAIClient(), "openai"

    raise LLMUnavailableError(
        "no LLM API key set. Export ANTHROPIC_API_KEY or OPENAI_API_KEY "
        "(or put it in .env) to enable --llm."
    )


def _key_is_real(value: str | None) -> bool:
    """Reject empty / placeholder / mostly-asterisk values."""
    if not value:
        return False
    s = value.strip()
    if len(s) < 20:
        return False
    # Common placeholder patterns we ship in .env / .env.example.
    if "xxxx" in s.lower() or s.count("*") > len(s) / 2:
        return False
    return True
