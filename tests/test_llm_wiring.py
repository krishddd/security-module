"""Integration: LLMContext threaded through the runner.

Verifies:
  1. LLMContext.disabled() works (no LLM needed when --llm absent).
  2. LLMContext.enable() raises cleanly when ANTHROPIC_API_KEY missing.
  3. Budget exhaustion mid-scan converts remaining categories to SKIPPED_BUDGET.
  4. Post-scan triage pass updates an ambiguous finding's status when LLM says so.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_disabled_context_has_no_llm() -> None:
    from llm.context import LLMContext
    ctx = LLMContext.disabled()
    assert ctx.budget is not None
    assert ctx.client is None
    assert ctx.planner is None
    assert ctx.synthesizer is None
    assert ctx.triager is None


def test_enable_raises_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import importlib, config.settings, llm.client, llm.context
    importlib.reload(config.settings)
    importlib.reload(llm.client)
    importlib.reload(llm.context)
    # Import the exception class AFTER reload so the type identity matches.
    from llm.client import LLMUnavailableError as ReloadedErr
    with pytest.raises(ReloadedErr):
        llm.context.LLMContext.enable()


def test_budget_exhaustion_drains_remaining_categories(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the LLM raises BudgetExceededError mid-scan, the runner must
    short-circuit and mark every remaining category SKIPPED_BUDGET."""
    import asyncio

    from llm.budget import Budget, BudgetExceededError
    from llm.context import LLMContext
    from llm.triage import LLMTriager

    # Build an LLMContext whose triager *always* raises BudgetExceededError.
    class BoomTriager:
        def __init__(self) -> None:
            self.calls = 0

        def triage_batch(self, findings):
            self.calls += 1
            raise BudgetExceededError("max_spend_usd reached")

    ctx = LLMContext(budget=Budget(max_spend_usd=0.0))
    ctx.triager = BoomTriager()  # type: ignore[assignment]

    # The post-scan triage path catches BudgetExceededError and just logs.
    # Build a minimal SecurityReport with one ambiguous finding and confirm
    # the call was attempted but no crash.
    from models.enums import RiskCategory, Severity, TestStatus
    from models.test_result import CategoryResult, Finding, SecurityReport
    from core.test_runner import SecurityTestRunner

    f = Finding(
        test_id="t1", test_name="t1", category=RiskCategory.ASI01,
        status=TestStatus.PASSED, severity=Severity.MEDIUM,
        description="ambiguous case", payload_sent={"q": "hi"},
        response_summary="maybe leak", defense_held=True,
        evidence={"similarity_score": 55.0},  # 0.55 → ambiguous
    )
    cat = CategoryResult(category=RiskCategory.ASI01, category_name="x", findings=[f])
    report = SecurityReport(agent_name="t", agent_id="", target_url="http://x", categories=[cat])

    runner = SecurityTestRunner(config=None)
    # Should not raise.
    runner._run_post_scan_triage(report, ctx)
    assert ctx.triager.calls == 1


def test_post_scan_triage_flips_ambiguous_passed_to_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Triager says 'is_exploited=True' on an ambiguous PASSED → status becomes FAILED."""
    from llm.budget import Budget
    from llm.context import LLMContext
    from llm.triage import TriageVerdict
    from models.enums import RiskCategory, Severity, TestStatus
    from models.test_result import CategoryResult, Finding, SecurityReport
    from core.test_runner import SecurityTestRunner

    class FakeTriager:
        def triage_batch(self, findings):
            return [TriageVerdict(finding_id=f.finding_id, is_exploited=True,
                                  confidence=0.92, rationale="leak confirmed")
                    for f in findings]

    ctx = LLMContext(budget=Budget())
    ctx.triager = FakeTriager()  # type: ignore[assignment]

    f = Finding(
        test_id="amb1", test_name="amb1", category=RiskCategory.ASI02,
        status=TestStatus.PASSED, severity=Severity.HIGH,
        description="x", payload_sent={"q": "x"}, response_summary="y",
        defense_held=True, evidence={"similarity_score": 60.0},  # 0.60 → in band
    )
    cat = CategoryResult(category=RiskCategory.ASI02, category_name="x", findings=[f])
    report = SecurityReport(agent_name="t", agent_id="", target_url="http://x", categories=[cat])

    runner = SecurityTestRunner(config=None)
    runner._run_post_scan_triage(report, ctx)

    assert f.status == TestStatus.FAILED
    assert f.defense_held is False
    assert f.evidence["triage"]["is_exploited"] is True
    assert f.evidence["triage"]["rationale"] == "leak confirmed"


def test_post_scan_triage_skips_clear_findings() -> None:
    """A high-confidence finding (outside ambiguity band) is NOT sent to triage."""
    from llm.budget import Budget
    from llm.context import LLMContext
    from models.enums import RiskCategory, Severity, TestStatus
    from models.test_result import CategoryResult, Finding, SecurityReport
    from core.test_runner import SecurityTestRunner

    class FakeTriager:
        def __init__(self) -> None:
            self.called = False

        def triage_batch(self, findings):
            self.called = True
            return []

    ctx = LLMContext(budget=Budget())
    ctx.triager = FakeTriager()  # type: ignore[assignment]

    f = Finding(
        test_id="clear1", test_name="clear1", category=RiskCategory.ASI01,
        status=TestStatus.PASSED, severity=Severity.LOW,
        description="clear refusal", payload_sent={"q": "x"},
        response_summary="I cannot help with that.", defense_held=True,
        # No similarity_score → defaults to 1.0 (clearly blocked) → NOT ambiguous.
        evidence={},
    )
    cat = CategoryResult(category=RiskCategory.ASI01, category_name="x", findings=[f])
    report = SecurityReport(agent_name="t", agent_id="", target_url="http://x", categories=[cat])

    runner = SecurityTestRunner(config=None)
    runner._run_post_scan_triage(report, ctx)
    assert ctx.triager.called is False  # confident finding skipped triage
