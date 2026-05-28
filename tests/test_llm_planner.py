"""LLMTestPlanner: uses LLM output when present, falls back cleanly otherwise."""

from __future__ import annotations

import pytest

from llm.client import LLMResponse, LLMUsage
from llm.planner import LLMTestPlanner
from models.agent_profile import AgentCapability, AgentProfile
from models.enums import RiskCategory


def _profile() -> AgentProfile:
    return AgentProfile(
        name="stub", base_url="http://example.com",
        inferred_capabilities=[AgentCapability.SQL_QUERY],
        data_domains=["financial"],
    )


def test_planner_uses_llm_decision_when_present() -> None:
    class Fake:
        def message(self, **kwargs):
            categories = [
                {"category": "ASI01", "include": True, "priority": 5, "max_payloads": 10},
                {"category": "ASI02", "include": True, "priority": 8, "max_payloads": 30, "use_llm_synthesis": True},
                {"category": "ASI05", "include": False, "skip_reason": "no code-exec capability"},
            ]
            return LLMResponse(
                text="",
                tool_uses=[{"id": "x", "name": "submit_plan", "input": {"categories": categories, "notes": "ok"}}],
                usage=LLMUsage(input_tokens=500, output_tokens=200),
                model=kwargs["model"],
            )

    planner = LLMTestPlanner(Fake())  # type: ignore[arg-type]
    plan = planner.plan(_profile())

    assert plan.planner == "llm"
    asi01 = plan.find(RiskCategory.ASI01)
    assert asi01 and asi01.include and asi01.priority == 5 and asi01.max_payloads == 10
    asi02 = plan.find(RiskCategory.ASI02)
    assert asi02 and asi02.use_llm_synthesis is True
    asi05 = plan.find(RiskCategory.ASI05)
    assert asi05 and asi05.include is False
    assert asi05.skip_reason == "no code-exec capability"


def test_planner_fills_unspecified_categories_with_defaults() -> None:
    """LLM only returns 2 categories; planner must fill in the rest with include=True."""
    class Fake:
        def message(self, **kwargs):
            return LLMResponse(
                text="",
                tool_uses=[{"id": "x", "name": "submit_plan", "input": {"categories": [
                    {"category": "ASI01", "include": True, "priority": 10},
                ]}}],
                usage=LLMUsage(input_tokens=100, output_tokens=50),
                model=kwargs["model"],
            )

    planner = LLMTestPlanner(Fake())  # type: ignore[arg-type]
    plan = planner.plan(_profile())

    # Every RiskCategory appears in the plan.
    cats = {c.category for c in plan.categories}
    assert cats == set(RiskCategory)
    # Unspecified ones default to include=True with priority 50.
    asi08 = plan.find(RiskCategory.ASI08)
    assert asi08 and asi08.include is True and asi08.priority == 50


def test_planner_falls_back_when_llm_does_not_call_tool() -> None:
    class Fake:
        def message(self, **kwargs):
            return LLMResponse(text="just text, no tool call", tool_uses=[], usage=LLMUsage(), model=kwargs["model"])

    planner = LLMTestPlanner(Fake())  # type: ignore[arg-type]
    plan = planner.plan(_profile())
    assert plan.planner == "stub"  # fell back


def test_planner_falls_back_on_llm_exception() -> None:
    class BoomClient:
        def message(self, **kwargs):
            raise RuntimeError("rate limited")

    planner = LLMTestPlanner(BoomClient())  # type: ignore[arg-type]
    plan = planner.plan(_profile())
    assert plan.planner == "stub"  # fell back, scan can still proceed
