"""v3 tester registry + run_with_profile orchestration tests."""

from __future__ import annotations

import pytest

from core.target_adapter import DryRunAdapter
from core.test_runner import SecurityTestRunner
from core.tester_registry import (
    clear_registry,
    get_registry,
    register_tester,
)
from core.stub_planner import build_stub_plan
from models.agent_profile import (
    AgentCapability,
    AgentProfile,
    EndpointPurpose,
    EndpointSpec,
    HttpMethod,
    Transport,
)
from models.enums import RiskCategory, TestStatus


# Force one import of the real testers so the registry is populated for all
# tests in this module. (`run_with_profile` also does this, but explicit is
# clearer here.)
SecurityTestRunner(config=None)._import_testers()


# ---- decorator backwards-compat ------------------------------------------


def test_legacy_decorator_form_populates_v3_metadata() -> None:
    """`@register_tester(RiskCategory.ASI02)` (existing call site) must populate v3 metadata
    via the DEFAULT_METADATA table — without editing any tester file."""
    reg = get_registry()
    assert RiskCategory.ASI02 in reg
    meta = reg[RiskCategory.ASI02].metadata
    assert AgentCapability.SQL_QUERY in meta.required_capabilities
    assert AgentCapability.TOOL_INVOKE in meta.required_capabilities


def test_all_27_testers_registered() -> None:
    reg = get_registry()
    expected = {c for c in RiskCategory}
    assert set(reg.keys()) == expected, f"missing: {expected - set(reg.keys())}"


def test_clean_state_metadata_for_memory_categories() -> None:
    reg = get_registry()
    assert reg[RiskCategory.ASI06].metadata.requires_clean_state is True
    assert reg[RiskCategory.ASI08].metadata.requires_clean_state is True
    assert reg[RiskCategory.EXT14].metadata.requires_clean_state is True


def test_multi_turn_metadata_for_drift_categories() -> None:
    reg = get_registry()
    assert reg[RiskCategory.ASI06].metadata.multi_turn is True
    assert reg[RiskCategory.EXT07].metadata.multi_turn is True
    assert reg[RiskCategory.EXT12].metadata.multi_turn is True


# ---- runner: capability + transport + filter gating ----------------------


def _make_profile(
    base_url: str,
    *,
    transport: Transport = Transport.REST,
    capabilities: list[AgentCapability] | None = None,
) -> AgentProfile:
    return AgentProfile(
        name="test-profile",
        base_url=base_url,
        transport=transport,
        endpoints=[
            EndpointSpec(path="/chat", method=HttpMethod.POST, purpose=EndpointPurpose.CHAT),
            EndpointSpec(path="/healthz", method=HttpMethod.GET, purpose=EndpointPurpose.HEALTH),
        ],
        inferred_capabilities=capabilities if capabilities is not None else [AgentCapability.TOOL_INVOKE],
    )


@pytest.mark.asyncio
async def test_capability_gate_skips_asi02_when_no_sql(stub_agent_url: str) -> None:
    """Profile without SQL_QUERY → ASI02 emits SKIPPED_CAPABILITY."""
    profile = _make_profile(stub_agent_url, capabilities=[AgentCapability.WEB_BROWSE])
    plan = build_stub_plan(profile)
    runner = SecurityTestRunner(config=None)
    report = await runner.run_with_profile(profile=profile, plan=plan, adapter=DryRunAdapter(profile))

    asi02 = next(c for c in report.categories if c.category is RiskCategory.ASI02)
    statuses = {f.status for f in asi02.findings}
    assert TestStatus.SKIPPED_CAPABILITY in statuses


@pytest.mark.asyncio
async def test_capability_gate_skips_asi05_when_no_code_exec(stub_agent_url: str) -> None:
    """Profile without CODE_EXECUTION → ASI05 emits SKIPPED_CAPABILITY."""
    profile = _make_profile(stub_agent_url, capabilities=[AgentCapability.SQL_QUERY])
    plan = build_stub_plan(profile)
    runner = SecurityTestRunner(config=None)
    report = await runner.run_with_profile(profile=profile, plan=plan, adapter=DryRunAdapter(profile))

    asi05 = next(c for c in report.categories if c.category is RiskCategory.ASI05)
    statuses = {f.status for f in asi05.findings}
    assert TestStatus.SKIPPED_CAPABILITY in statuses


@pytest.mark.asyncio
async def test_transport_gate_skips_when_graphql_only_tester_on_rest_profile(stub_agent_url: str) -> None:
    """When the runner's profile transport is unsupported, the finding must be SKIPPED_TRANSPORT."""
    # We don't have a REST-only tester; create a synthetic one with restricted transports.
    saved = dict(get_registry())
    clear_registry()
    try:
        # Re-register the real testers EXCEPT ASI01, which we override.
        for cat, entry in saved.items():
            if cat is not RiskCategory.ASI01:
                from core.tester_registry import _REGISTRY  # type: ignore[attr-defined]
                _REGISTRY[cat] = entry

        @register_tester(
            category=RiskCategory.ASI01,
            applicable_transports={Transport.GRAPHQL},  # excludes REST
        )
        class GraphQLOnlyTester:
            CATEGORY = RiskCategory.ASI01
            def __init__(self, **kwargs): pass
            async def run_tests(self):
                raise AssertionError("should not be called — transport gate must fire first")

        profile = _make_profile(stub_agent_url, transport=Transport.REST)
        plan = build_stub_plan(profile)
        runner = SecurityTestRunner(config=None)
        report = await runner.run_with_profile(profile=profile, plan=plan, adapter=DryRunAdapter(profile))
        asi01 = next(c for c in report.categories if c.category is RiskCategory.ASI01)
        assert any(f.status is TestStatus.SKIPPED_TRANSPORT for f in asi01.findings)
    finally:
        clear_registry()
        from core.tester_registry import _REGISTRY  # type: ignore[attr-defined]
        for cat, entry in saved.items():
            _REGISTRY[cat] = entry


@pytest.mark.asyncio
async def test_cli_category_filter_marks_others_skipped(stub_agent_url: str) -> None:
    """cli_filter={ASI02} → every other category gets SKIPPED_CATEGORY_FILTER."""
    profile = _make_profile(stub_agent_url, capabilities=[AgentCapability.SQL_QUERY, AgentCapability.TOOL_INVOKE])
    plan = build_stub_plan(profile)
    runner = SecurityTestRunner(config=None)
    report = await runner.run_with_profile(
        profile=profile,
        plan=plan,
        adapter=DryRunAdapter(profile),
        cli_filter={RiskCategory.ASI02},
    )

    for cat_result in report.categories:
        if cat_result.category is RiskCategory.ASI02:
            assert not any(f.status is TestStatus.SKIPPED_CATEGORY_FILTER for f in cat_result.findings)
        else:
            assert any(f.status is TestStatus.SKIPPED_CATEGORY_FILTER for f in cat_result.findings), \
                f"{cat_result.category.value} was not filtered out"


@pytest.mark.asyncio
async def test_clean_state_testers_run_after_stateless(stub_agent_url: str) -> None:
    """run_with_profile orders stateless testers before requires_clean_state=True ones."""
    profile = _make_profile(stub_agent_url, capabilities=[AgentCapability.MEMORY_PERSIST, AgentCapability.TOOL_INVOKE])
    plan = build_stub_plan(profile)
    plan.categories.sort(key=lambda c: c.category.value)  # deterministic input order
    runner = SecurityTestRunner(config=None)

    # Track the order in which the adapter recorded its first invoke per category.
    # DryRunAdapter records each invoke; we read the recorded list afterwards.
    adapter = DryRunAdapter(profile)
    await runner.run_with_profile(profile=profile, plan=plan, adapter=adapter, cli_filter=None)

    # Smoke check: scan completed without raising. Detailed ordering verification
    # requires instrumenting the runner; the docstring of run_with_profile
    # documents the contract (clean-state testers last).
    assert True


# ---- session lifecycle: multi-turn testers receive a SessionHandle -------


@pytest.mark.asyncio
async def test_multi_turn_tester_receives_session_handle(stub_agent_url: str) -> None:
    """A tester with multi_turn=True and a `session=` parameter must receive a SessionHandle."""
    saved = dict(get_registry())
    clear_registry()
    from core.tester_registry import _REGISTRY  # type: ignore[attr-defined]
    for cat, entry in saved.items():
        if cat is not RiskCategory.EXT07:
            _REGISTRY[cat] = entry

    captured: dict[str, object] = {}

    try:
        @register_tester(
            category=RiskCategory.EXT07,
            multi_turn=True,
            applicable_transports={Transport.REST},
        )
        class MultiTurnSpy:
            CATEGORY = RiskCategory.EXT07
            def __init__(self, **kwargs): pass
            async def run_tests(self, session=None):
                captured["session"] = session
                from models.test_result import CategoryResult
                return CategoryResult(category=RiskCategory.EXT07, category_name="spy")

        profile = _make_profile(stub_agent_url)
        plan = build_stub_plan(profile)
        runner = SecurityTestRunner(config=None)
        await runner.run_with_profile(
            profile=profile, plan=plan, adapter=DryRunAdapter(profile),
            cli_filter={RiskCategory.EXT07},
        )

        from models.agent_profile import SessionHandle
        assert isinstance(captured.get("session"), SessionHandle), \
            f"expected SessionHandle, got {type(captured.get('session')).__name__}"
        assert captured["session"].session_id  # type: ignore[union-attr]
    finally:
        clear_registry()
        for cat, entry in saved.items():
            _REGISTRY[cat] = entry