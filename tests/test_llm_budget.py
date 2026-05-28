"""Budget governance: pricing, cap enforcement, snapshot."""

from __future__ import annotations

import pytest

from llm.budget import Budget, BudgetExceededError, price_call
from llm.client import LLMResponse, LLMUsage


def _resp(model: str = "claude-sonnet-4-6", input_tokens: int = 1000, output_tokens: int = 500) -> LLMResponse:
    return LLMResponse(
        text="ok",
        usage=LLMUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        model=model,
    )


def test_price_call_sonnet() -> None:
    cost = price_call("claude-sonnet-4-6", _resp(input_tokens=1_000_000, output_tokens=1_000_000))
    # $3 in + $15 out per 1M = $18.
    assert 17.9 <= cost <= 18.1


def test_price_call_unknown_model_uses_sonnet_fallback() -> None:
    cost = price_call("claude-imaginary", _resp(input_tokens=1_000_000, output_tokens=0))
    assert 2.9 <= cost <= 3.1


def test_budget_charge_accumulates() -> None:
    b = Budget()
    c1 = b.charge("claude-sonnet-4-6", _resp(input_tokens=1000))
    c2 = b.charge("claude-sonnet-4-6", _resp(input_tokens=1000))
    assert b.calls_made == 2
    assert abs(b.spend_usd - (c1 + c2)) < 1e-9


def test_budget_max_calls_enforced() -> None:
    b = Budget(max_calls=2)
    b.charge("claude-sonnet-4-6", _resp())
    with pytest.raises(BudgetExceededError, match="max_calls=2"):
        b.charge("claude-sonnet-4-6", _resp())


def test_budget_max_spend_enforced() -> None:
    b = Budget(max_spend_usd=0.001)
    with pytest.raises(BudgetExceededError, match="max_spend_usd"):
        for _ in range(5):
            b.charge("claude-opus-4-7", _resp(input_tokens=100_000, output_tokens=10_000))


def test_budget_snapshot_shape() -> None:
    b = Budget(max_calls=10, max_spend_usd=1.0)
    b.charge("claude-sonnet-4-6", _resp())
    snap = b.snapshot()
    assert snap["calls_made"] == 1
    assert snap["max_calls"] == 10
    assert snap["max_spend_usd"] == 1.0
    assert snap["spend_usd"] > 0
