"""LLM budget governance.

A single ``Budget`` instance is created per scan. Every ``ClaudeClient``
call goes through ``Budget.charge(response)`` which:

  * counts the call;
  * accrues input/output token costs from ``LLMUsage``;
  * raises ``BudgetExceededError`` when either ``max_calls`` or
    ``max_spend_usd`` is exhausted.

Callers should catch ``BudgetExceededError`` and mark the affected
category ``SKIPPED_BUDGET`` rather than crashing.

Pricing constants are deliberately conservative — meant for a pre-scan
*estimate*, not financial accounting. The Anthropic API returns exact
usage; the per-million-tokens rates below come from publicly listed
prices and are easy to adjust as they evolve.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from config.settings import LLM_MODEL_PAYLOAD, LLM_MODEL_PLANNER, LLM_MODEL_TRIAGE
from llm.client import LLMResponse


# USD per 1M tokens. Tuple is (input, output, cache_write, cache_read).
# Values approximate the public list; override at runtime via PRICING_OVERRIDE.
_DEFAULT_PRICING: dict[str, tuple[float, float, float, float]] = {
    # Opus 4.7
    "claude-opus-4-7": (15.00, 75.00, 18.75, 1.50),
    "claude-opus-4-5": (15.00, 75.00, 18.75, 1.50),
    # Sonnet 4.6 / 4.5
    "claude-sonnet-4-6": (3.00, 15.00, 3.75, 0.30),
    "claude-sonnet-4-5": (3.00, 15.00, 3.75, 0.30),
    # Haiku 4.5
    "claude-haiku-4-5-20251001": (0.80, 4.00, 1.00, 0.08),
    "claude-haiku-4-5": (0.80, 4.00, 1.00, 0.08),
    # ---- OpenAI (cache_write rate not applicable; cache_read is the discounted input rate) ----
    "gpt-4o":         (2.50, 10.00, 2.50, 1.25),
    "gpt-4o-mini":    (0.15,  0.60, 0.15, 0.075),
    "gpt-4.1":        (2.00,  8.00, 2.00, 0.50),
    "gpt-4.1-mini":   (0.40,  1.60, 0.40, 0.10),
    "gpt-4.1-nano":   (0.10,  0.40, 0.10, 0.025),
    "gpt-5":          (1.25, 10.00, 1.25, 0.125),
    "gpt-5-mini":     (0.25,  2.00, 0.25, 0.025),
    "gpt-5-nano":     (0.05,  0.40, 0.05, 0.005),
    "o3-mini":        (1.10,  4.40, 1.10, 0.55),
}


def price_call(model: str, response: LLMResponse) -> float:
    """USD cost for a single call."""
    rates = _DEFAULT_PRICING.get(model)
    if rates is None:
        # Unknown model — fall back to Sonnet pricing rather than $0.
        rates = _DEFAULT_PRICING["claude-sonnet-4-6"]
    in_rate, out_rate, cw_rate, cr_rate = rates
    u = response.usage
    return (
        u.input_tokens * in_rate / 1_000_000
        + u.output_tokens * out_rate / 1_000_000
        + u.cache_creation_input_tokens * cw_rate / 1_000_000
        + u.cache_read_input_tokens * cr_rate / 1_000_000
    )


class BudgetExceededError(RuntimeError):
    """Raised when either the call cap or the spend cap is hit."""


@dataclass
class Budget:
    """Per-scan LLM spend cap."""

    max_calls: int | None = None
    max_spend_usd: float | None = None
    calls_made: int = 0
    spend_usd: float = 0.0
    history: list[dict] = field(default_factory=list)

    # ---- pre-flight check (used by --dry-run / plan output) ---------

    def project(self, *, extra_calls: int, est_cost_per_call_usd: float) -> tuple[int, float]:
        """Return projected (calls, $) if ``extra_calls`` more were made."""
        return self.calls_made + extra_calls, self.spend_usd + extra_calls * est_cost_per_call_usd

    # ---- charge a call ------------------------------------------------

    def charge(self, model: str, response: LLMResponse) -> float:
        """Record one call. Returns its cost in USD.

        Raises ``BudgetExceededError`` if either cap is now exhausted.
        The call is still counted — callers should fail the *next* call,
        not refund this one.
        """
        cost = price_call(model, response)
        self.calls_made += 1
        self.spend_usd += cost
        self.history.append({"model": model, "cost_usd": cost, "usage": response.usage.__dict__})

        if self.max_calls is not None and self.calls_made >= self.max_calls:
            raise BudgetExceededError(
                f"max_calls={self.max_calls} reached (spend so far: ${self.spend_usd:.4f})"
            )
        if self.max_spend_usd is not None and self.spend_usd >= self.max_spend_usd:
            raise BudgetExceededError(
                f"max_spend_usd=${self.max_spend_usd:.4f} reached "
                f"(calls so far: {self.calls_made})"
            )
        return cost

    # ---- snapshot for reports ----------------------------------------

    def snapshot(self) -> dict:
        return {
            "calls_made": self.calls_made,
            "spend_usd": round(self.spend_usd, 6),
            "max_calls": self.max_calls,
            "max_spend_usd": self.max_spend_usd,
        }
