"""Tests for parallel suite execution in run_with_profile (Gap #6).

Proves that stateless single-turn suites run concurrently while clean-state and
multi-turn suites stay isolated (run alone), and that report order stays
deterministic.
"""

from __future__ import annotations

import asyncio

import pytest

from core.base_tester import BaseASITester
from core.stub_planner import build_stub_plan
from core.target_adapter import DryRunAdapter
from core.test_runner import SecurityTestRunner
from core.tester_registry import clear_registry, get_registry, register_tester
from models.agent_profile import (
    AgentProfile,
    EndpointPurpose,
    EndpointSpec,
    HttpMethod,
    Transport,
)
from models.enums import RiskCategory
from models.test_result import CategoryResult


def _profile(url: str) -> AgentProfile:
    return AgentProfile(
        name="parallel-test", base_url=url, transport=Transport.REST,
        endpoints=[EndpointSpec(path="/chat", method=HttpMethod.POST, purpose=EndpointPurpose.CHAT)],
        inferred_capabilities=[],
    )


@pytest.mark.asyncio
async def test_stateless_suites_run_concurrently_clean_state_isolated(stub_agent_url: str) -> None:
    saved = dict(get_registry())
    clear_registry()
    from core.tester_registry import _REGISTRY  # type: ignore[attr-defined]

    tracker = {"active": 0, "max": 0}
    peers_seen: dict[RiskCategory, int] = {}

    def make_tester(cat: RiskCategory, *, clean: bool = False, multi: bool = False):
        @register_tester(
            category=cat,
            required_capabilities=frozenset(),
            applicable_transports=frozenset({Transport.REST}),
            requires_clean_state=clean,
            multi_turn=multi,
        )
        class _Fake(BaseASITester):
            CATEGORY = cat

            def __init__(self, **kwargs):
                super().__init__(**kwargs)

            async def run_tests(self, session=None) -> CategoryResult:
                tracker["active"] += 1
                tracker["max"] = max(tracker["max"], tracker["active"])
                # Peers concurrently active when THIS suite started.
                peers_seen[cat] = max(peers_seen.get(cat, 0), tracker["active"] - 1)
                await asyncio.sleep(0.15)
                tracker["active"] -= 1
                return CategoryResult(category=cat, category_name=cat.title)

        return _Fake

    try:
        stateless = [RiskCategory.ASI01, RiskCategory.ASI03, RiskCategory.ASI04]
        for c in stateless:
            make_tester(c)
        make_tester(RiskCategory.ASI08, clean=True)   # requires_clean_state
        make_tester(RiskCategory.EXT07, multi=True)    # multi_turn

        profile = _profile(stub_agent_url)
        plan = build_stub_plan(profile)
        runner = SecurityTestRunner(config=None)
        report = await runner.run_with_profile(
            profile=profile, plan=plan, adapter=DryRunAdapter(profile),
        )

        # Stateless suites overlapped in time.
        assert tracker["max"] >= 2, f"expected concurrency, saw max={tracker['max']}"
        # At least one stateless suite observed a peer running alongside it.
        assert max(peers_seen[c] for c in stateless) >= 1
        # Clean-state and multi-turn suites ran ALONE (no peers).
        assert peers_seen[RiskCategory.ASI08] == 0, "clean-state suite must not overlap"
        assert peers_seen[RiskCategory.EXT07] == 0, "multi-turn suite must not overlap"

        # Report order stays deterministic (RiskCategory enum order).
        order = list(RiskCategory)
        cats = [c.category for c in report.categories]
        assert cats == sorted(cats, key=order.index)
        # All five fakes produced a result.
        ran = {c.category for c in report.categories if c.tests_run > 0 or c.category in
               (*stateless, RiskCategory.ASI08, RiskCategory.EXT07)}
        for c in (*stateless, RiskCategory.ASI08, RiskCategory.EXT07):
            assert c in {cr.category for cr in report.categories}
    finally:
        clear_registry()
        for cat, entry in saved.items():
            _REGISTRY[cat] = entry


@pytest.mark.asyncio
async def test_category_disposition_run_vs_filter(stub_agent_url: str) -> None:
    """_category_disposition returns a run-spec normally and a skip under filter."""
    runner = SecurityTestRunner(config=None)
    runner._import_testers()
    from core.tester_registry import get_registry as _get

    registry = _get()
    profile = _profile(stub_agent_url)
    plan = build_stub_plan(profile)

    run = runner._category_disposition(
        RiskCategory.ASI01, registry, plan, None, Transport.REST, set(),
    )
    assert run[0] == "run"

    skipped = runner._category_disposition(
        RiskCategory.ASI01, registry, plan, {RiskCategory.ASI02}, Transport.REST, set(),
    )
    assert skipped[0] == "skip"
    from models.enums import TestStatus
    assert any(f.status is TestStatus.SKIPPED_CATEGORY_FILTER for f in skipped[1].findings)
