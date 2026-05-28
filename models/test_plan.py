"""TestPlan model — produced by ``cli plan``, consumed by ``cli scan``.

A plan is the runner's instructions for one scan: which categories run,
in what order, with what budget. The LLM planner (Phase 6) emits one of
these; the Phase 3 stub planner builds one by enabling every category at
default priority.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .enums import RiskCategory


class CategoryPlan(BaseModel):
    category: RiskCategory
    include: bool = True
    priority: int = 50  # 0 = run first, 100 = run last
    skip_reason: str | None = None
    max_payloads: int = 20
    use_llm_synthesis: bool = False


class CostEstimate(BaseModel):
    """Pre-scan budget projection. All zero when --llm is off."""

    projected_llm_calls: int = 0
    projected_input_tokens: int = 0
    projected_output_tokens: int = 0
    projected_usd: float = 0.0
    notes: list[str] = Field(default_factory=list)


class TestPlan(BaseModel):
    schema_version: Literal["3.0"] = "3.0"
    profile_name: str
    profile_agent_id: str = ""
    categories: list[CategoryPlan] = Field(default_factory=list)
    cost_estimate: CostEstimate = Field(default_factory=CostEstimate)
    planner: Literal["stub", "llm"] = "stub"
    notes: str = ""

    # ---- convenience -----------------------------------------------------

    def included_categories(self) -> list[CategoryPlan]:
        return [c for c in self.categories if c.include]

    def find(self, cat: RiskCategory) -> CategoryPlan | None:
        for c in self.categories:
            if c.category == cat:
                return c
        return None
