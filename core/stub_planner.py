"""Phase-3 stub planner.

Builds a ``TestPlan`` from an ``AgentProfile`` without calling any LLM:

  * every category is included by default
  * categories whose required capabilities are *clearly* absent are
    filtered out with ``skip_reason``
  * priority is derived from the category's default severity

The real LLM-driven planner ships in Phase 6 (``llm/planner.py``) and
follows the same output shape.
"""

from __future__ import annotations

from models.agent_profile import AgentCapability, AgentProfile
from models.enums import RiskCategory, Severity
from models.test_plan import CategoryPlan, CostEstimate, TestPlan

# Coarse capability requirements per category. Conservative: a category is
# only skipped here if the profile demonstrably lacks the capability — we
# never skip silently. The LLM planner refines this with full context.
_CATEGORY_CAPABILITY_HINTS: dict[RiskCategory, set[AgentCapability]] = {
    RiskCategory.ASI02: {AgentCapability.SQL_QUERY, AgentCapability.TOOL_INVOKE},
    RiskCategory.ASI05: {AgentCapability.CODE_EXECUTION, AgentCapability.SHELL_EXEC},
    RiskCategory.EXT15: {AgentCapability.SQL_QUERY},
    RiskCategory.EXT17: {AgentCapability.EMAIL_SEND},
}

_SEVERITY_PRIORITY = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 30,
    Severity.MEDIUM: 50,
    Severity.LOW: 70,
    Severity.INFO: 90,
}


def build_stub_plan(profile: AgentProfile, *, max_payloads: int = 20) -> TestPlan:
    profile_caps = set(profile.inferred_capabilities)
    plans: list[CategoryPlan] = []

    for cat in RiskCategory:
        required = _CATEGORY_CAPABILITY_HINTS.get(cat)
        include = True
        skip_reason: str | None = None
        # Only skip when the capability hint is present AND the profile has
        # no overlap with it. AgentCapability.UNKNOWN counts as "we don't
        # know" — never used as a skip trigger.
        if required and profile_caps and not (profile_caps & required):
            if AgentCapability.UNKNOWN not in profile_caps:
                include = False
                skip_reason = (
                    f"profile lacks any of {sorted(c.value for c in required)}"
                )

        plans.append(
            CategoryPlan(
                category=cat,
                include=include,
                priority=_SEVERITY_PRIORITY.get(cat.default_severity, 50),
                skip_reason=skip_reason,
                max_payloads=max_payloads,
                use_llm_synthesis=False,
            )
        )

    plans.sort(key=lambda c: (c.priority, c.category.value))

    return TestPlan(
        profile_name=profile.name,
        profile_agent_id=profile.agent_id,
        categories=plans,
        cost_estimate=CostEstimate(notes=["stub planner: no LLM calls projected"]),
        planner="stub",
        notes="Phase-3 stub planner — every applicable category runs with seed payloads only.",
    )
