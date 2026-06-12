"""
Main test orchestrator with semaphore-controlled concurrency and risk scoring.
Coordinates health checking, baseline profiling, and sequential ASI category execution.
"""

from __future__ import annotations
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Type

from typing import Any

from core.http_client import AsyncHttpClient
from core.health_checker import HealthChecker, HealthStatus
from core.callback_server import CallbackServer
from core.base_tester import BaseASITester
from models.agent_config import AgentConfig
from models.enums import RiskCategory
from models.test_result import BaselineProfile, CategoryResult, SecurityReport
from config.settings import RESULTS_DIR

logger = logging.getLogger(__name__)


# v3 decorator + metadata-aware registry. The legacy single-arg form
# (`@register_tester(RiskCategory.X)`) still works — it delegates to the
# new module and gains default metadata from DEFAULT_METADATA.
from core.tester_registry import (
    register_tester as register_tester,
    get_registry as get_v3_registry,
    TesterMetadata,
)


class _LegacyRegistryView:
    """Read-only mapping that proxies the v3 registry, exposing only the class.

    Lets the existing `_TESTER_REGISTRY[category]` and `category in _TESTER_REGISTRY`
    call sites in `run_all()` keep working unchanged.
    """

    def __getitem__(self, key: RiskCategory) -> Type[BaseASITester]:
        return get_v3_registry()[key].cls

    def __contains__(self, key: object) -> bool:
        return key in get_v3_registry()

    def get(self, key: RiskCategory, default: Any = None) -> Any:
        entry = get_v3_registry().get(key)
        return entry.cls if entry else default

    def items(self):
        return [(cat, entry.cls) for cat, entry in get_v3_registry().items()]


_TESTER_REGISTRY = _LegacyRegistryView()


def _skip_finding(category: RiskCategory, status: Any, reason: str) -> Any:
    """Build a minimal Finding representing a skipped tester."""
    from models.enums import Severity
    from models.test_result import Finding
    return Finding(
        test_id=f"{category.value}_skipped",
        test_name="skipped",
        category=category,
        status=status,
        severity=Severity.INFO,
        description=reason,
        payload_sent={},
        response_summary=reason,
        defense_held=True,
    )


def _accepts_session(tester: Any) -> bool:
    """True if tester.run_tests has a ``session`` parameter."""
    import inspect
    try:
        return "session" in inspect.signature(tester.run_tests).parameters
    except (TypeError, ValueError):
        return False


class SecurityTestRunner:
    """
    Orchestrates OWASP ASI Top 10 security test execution.
    Runs health check, baseline profiling, then sequential category tests.

    Two entry points:
      * ``run_all(...)``           — legacy path, takes AgentConfig
      * ``run_with_profile(...)``  — v3 path, takes AgentProfile + TestPlan + adapter
    """

    def __init__(self, config: AgentConfig | None = None):
        self.config = config
        self.client = (
            AsyncHttpClient(
                base_url=config.base_url,
                timeout_s=config.timeout_seconds,
                auth_headers=config.auth_headers,
            )
            if config is not None
            else None
        )
        self.callback_server = CallbackServer()
        self.health_status: HealthStatus | None = None
        self.baseline: BaselineProfile = BaselineProfile()

    async def run_all(
        self,
        categories: list[RiskCategory] | None = None,
        skip_baseline: bool = False,
        output_dir: str | Path | None = None,
    ) -> SecurityReport:
        """
        Execute full security assessment.
        Categories default to all 10 ASI categories if not specified.
        """
        start = time.perf_counter()
        target_categories = categories or list(RiskCategory)

        # Import all tester modules to trigger registration
        self._import_testers()

        # Pre-flight health check
        logger.info(f"Starting OWASP ASI assessment against {self.config.name}")
        logger.info(f"Target: {self.config.base_url}")

        checker = HealthChecker(self.client, self.config)
        self.health_status = await checker.check(run_baseline=not skip_baseline)

        if not self.health_status.healthy:
            logger.error("Health check FAILED — aborting scan")
            report = SecurityReport(
                agent_name=self.config.name,
                agent_id=self.config.agent_id,
                target_url=self.config.base_url,
                summary="Scan aborted: target agent health check failed.",
            )
            return report

        self.baseline = self.health_status.baseline
        logger.info(f"Health OK. {len(self.health_status.available_endpoints)} endpoints reachable.")

        # Start OOB callback server
        await self.callback_server.start()

        # Execute categories sequentially (to avoid overloading local LLM)
        report = SecurityReport(
            agent_name=self.config.name,
            agent_id=self.config.agent_id,
            target_url=self.config.base_url,
            baseline=self.baseline,
        )

        for category in target_categories:
            if category not in _TESTER_REGISTRY:
                logger.warning(f"No tester registered for {category.value} — skipping")
                continue

            logger.info(f"\n{'='*60}")
            logger.info(f"Running {category.value}: {category.title}")
            logger.info(f"{'='*60}")

            try:
                result = await self.run_category(category)
                report.categories.append(result)
                logger.info(
                    f"{category.value} complete: "
                    f"{result.tests_passed} held, {result.tests_failed} vulnerable, "
                    f"risk={result.risk_score:.1f}"
                )
            except Exception as e:
                logger.error(f"{category.value} failed with exception: {e}", exc_info=True)
                # Create error result for this category
                error_result = CategoryResult(
                    category=category,
                    category_name=category.title,
                )
                report.categories.append(error_result)

        # Compute overall scores
        report.duration_seconds = time.perf_counter() - start
        report.compute_overall_score()
        report.compute_summary()

        # Cleanup
        await self.callback_server.stop()
        await self.client.close()

        # Save results
        out = output_dir or RESULTS_DIR
        await self._save_results(report, Path(out))

        logger.info(f"\n{'='*60}")
        logger.info(f"ASSESSMENT COMPLETE in {report.duration_seconds:.1f}s")
        logger.info(report.summary)
        logger.info(f"{'='*60}")

        return report

    async def run_category(self, category: RiskCategory) -> CategoryResult:
        """Run a single ASI category's tests."""
        tester_cls = _TESTER_REGISTRY.get(category)
        if not tester_cls:
            raise ValueError(f"No tester for {category.value}")

        tester = tester_cls(
            client=self.client,
            config=self.config,
            baseline=self.baseline,
            callback_url=self.callback_server.callback_url,
        )

        cat_start = time.perf_counter()
        result = await tester.run_tests()
        result.duration_seconds = time.perf_counter() - cat_start
        return result

    async def _save_results(self, report: SecurityReport, output_dir: Path) -> None:
        """Save report to structured output directory."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = report.agent_name.replace(" ", "_").replace("/", "_")
        run_dir = output_dir / f"{ts}_{safe_name}"
        findings_dir = run_dir / "findings"
        logs_dir = run_dir / "logs"

        for d in [run_dir, findings_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Full report JSON
        report_path = run_dir / "report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"Saved report: {report_path}")

        # Baseline profile
        baseline_path = run_dir / "baseline_profile.json"
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump(report.baseline.to_dict(), f, indent=2)

        # Per-category findings
        for cat_result in report.categories:
            cat_path = findings_dir / f"{cat_result.category.value.lower()}_{cat_result.category_name.lower().replace(' ', '_').replace('&', 'and')}.json"
            with open(cat_path, "w", encoding="utf-8") as f:
                json.dump(cat_result.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info(f"Results saved to: {run_dir}")

    # ─────────────────────────────────────────────────────────────────────
    # v3 entrypoint: profile + plan + adapter.
    #
    # Keeps the legacy `run_all(config)` path intact. v3 callers (cli.py
    # scan-v3) use this instead. Per-tester metadata from tester_registry
    # decides which categories actually execute vs. emit a SKIPPED_*
    # finding.
    # ─────────────────────────────────────────────────────────────────────
    async def run_with_profile(
        self,
        profile: Any,                         # AgentProfile — Any here to avoid circular import
        plan: Any,                            # TestPlan
        adapter: Any | None = None,           # TargetAdapter; constructed via make_adapter if None
        output_dir: str | Path | None = None,
        cli_filter: set[RiskCategory] | None = None,
        llm_context: Any | None = None,       # llm.context.LLMContext
    ) -> SecurityReport:
        """Run a v3 scan against ``profile`` according to ``plan``."""
        from datetime import datetime as _dt
        from core.target_adapter import make_adapter, TransportNotSupportedError
        from core.tester_registry import get_registry
        from models.enums import Severity, TestStatus
        from models.test_result import Finding

        start = time.perf_counter()
        self._import_testers()
        registry = get_registry()

        if adapter is None:
            adapter = make_adapter(profile)

        # Establish a latency baseline so DoS/timeout testers (ASI08, EXT*) can
        # use a relative threshold (p95 * multiplier). Without this the baseline
        # stays at its p95=0 default and every latency comparison (`latency < 0`)
        # registers as a vulnerability — the "threshold 0ms" false positives.
        if not self.baseline.samples:
            self.baseline = await self._establish_baseline_v3(adapter)

        # UNION: confirmed_capabilities can only ADD coverage, never replace.
        profile_caps = set(profile.inferred_capabilities) | set(
            getattr(profile, "confirmed_capabilities", None) or []
        )
        profile_transport = profile.transport

        report = SecurityReport(
            agent_name=profile.name,
            agent_id=getattr(profile, "agent_id", ""),
            target_url=str(profile.base_url),
            baseline=self.baseline,
        )

        # Order: stateless first, then `requires_clean_state=True` last so a
        # crashing/DoSing tester doesn't poison earlier ones.
        included = plan.included_categories()
        included.sort(key=lambda c: (
            registry.get(c.category).metadata.requires_clean_state if c.category in registry else False,
            c.priority,
        ))

        included_set = {c.category for c in included}

        try:
            for category in RiskCategory:
                entry = registry.get(category)
                category_result = CategoryResult(category=category, category_name=category.title)

                # CLI --category filter
                if cli_filter is not None and category not in cli_filter:
                    category_result.findings.append(_skip_finding(
                        category, TestStatus.SKIPPED_CATEGORY_FILTER,
                        "Excluded by --category filter",
                    ))
                    category_result.compute_stats()
                    report.categories.append(category_result)
                    continue

                # Plan-level skip (planner already filtered)
                cat_plan = plan.find(category) if hasattr(plan, "find") else None
                if cat_plan is not None and not cat_plan.include:
                    # Promote to a specific sub-status when the planner skipped
                    # for a recognizable reason so reports surface the WHY.
                    reason = cat_plan.skip_reason or "Skipped by planner"
                    status = TestStatus.SKIPPED
                    if "lacks" in reason.lower() or "capabilit" in reason.lower():
                        status = TestStatus.SKIPPED_CAPABILITY
                    category_result.findings.append(_skip_finding(category, status, reason))
                    category_result.compute_stats()
                    report.categories.append(category_result)
                    continue

                # No tester implementation registered
                if entry is None:
                    category_result.findings.append(_skip_finding(
                        category, TestStatus.SKIPPED,
                        "No tester implementation registered for this category",
                    ))
                    category_result.compute_stats()
                    report.categories.append(category_result)
                    continue

                meta: TesterMetadata = entry.metadata

                # Transport gating
                if profile_transport not in meta.applicable_transports:
                    category_result.findings.append(_skip_finding(
                        category, TestStatus.SKIPPED_TRANSPORT,
                        f"Tester does not support transport {profile_transport.value}",
                    ))
                    category_result.compute_stats()
                    report.categories.append(category_result)
                    continue

                # Capability gating — only skip when profile has SOME caps AND none overlap.
                if (
                    meta.required_capabilities
                    and profile_caps
                    and not (profile_caps & set(meta.required_capabilities))
                ):
                    category_result.findings.append(_skip_finding(
                        category, TestStatus.SKIPPED_CAPABILITY,
                        f"Profile lacks any of {sorted(c.value for c in meta.required_capabilities)}",
                    ))
                    category_result.compute_stats()
                    report.categories.append(category_result)
                    continue

                # Construct the tester with the adapter injected. Base
                # tester routes send_ask/send_to_endpoint through the
                # adapter when present (legacy testers transparently work
                # against an AgentProfile target).
                cat_start = time.perf_counter()
                try:
                    tester = entry.cls(
                        client=self.client,
                        config=getattr(self, "config", None),
                        baseline=self.baseline,
                        callback_url=self.callback_server.callback_url if self.callback_server else "",
                        adapter=adapter,
                    )
                    # Inject LLM context (testers that opt in use it; others ignore).
                    if llm_context is not None:
                        setattr(tester, "llm_context", llm_context)

                    if meta.multi_turn:
                        handle = await adapter.open_session()
                        try:
                            result = await tester.run_tests(session=handle) if _accepts_session(tester) else await tester.run_tests()
                        finally:
                            await adapter.close_session(handle)
                    else:
                        result = await tester.run_tests()

                    result.duration_seconds = time.perf_counter() - cat_start
                    report.categories.append(result)
                except TransportNotSupportedError as e:
                    category_result.findings.append(_skip_finding(
                        category, TestStatus.SKIPPED_TRANSPORT, str(e),
                    ))
                    category_result.compute_stats()
                    report.categories.append(category_result)
                except Exception as e:
                    # Budget-cap exhaustion bubbles up — mark this category and
                    # all REMAINING categories as SKIPPED_BUDGET, then stop.
                    if e.__class__.__name__ == "BudgetExceededError":
                        logger.warning("budget exhausted at %s; remaining categories will skip", category.value)
                        category_result.findings.append(_skip_finding(
                            category, TestStatus.SKIPPED_BUDGET, str(e),
                        ))
                        category_result.compute_stats()
                        report.categories.append(category_result)
                        # Drain remaining categories as SKIPPED_BUDGET.
                        remaining = [c for c in RiskCategory if c.value > category.value and c not in {cr.category for cr in report.categories}]
                        for rcat in remaining:
                            rc = CategoryResult(category=rcat, category_name=rcat.title)
                            rc.findings.append(_skip_finding(rcat, TestStatus.SKIPPED_BUDGET, "budget exhausted earlier in scan"))
                            rc.compute_stats()
                            report.categories.append(rc)
                        break
                    logger.error(f"{category.value} failed: {e}", exc_info=True)
                    err_cat = CategoryResult(category=category, category_name=category.title)
                    err_cat.findings.append(Finding(
                        test_id=f"{category.value}_runner_error",
                        test_name="runner_error",
                        category=category,
                        status=TestStatus.ERROR,
                        severity=Severity.INFO,
                        description=str(e),
                    ))
                    err_cat.compute_stats()
                    report.categories.append(err_cat)

                if meta.requires_clean_state:
                    try:
                        await adapter.reset_session()
                    except Exception as e:
                        logger.warning(f"reset_session() after {category.value} failed: {e}")
        finally:
            try:
                await adapter.close()
            except Exception:
                pass

        # Post-scan LLM triage pass: any findings whose detector confidence
        # lands in the ambiguity band get a second-opinion verdict from the
        # triager. Only runs when --llm was passed and budget allows.
        if llm_context is not None and getattr(llm_context, "triager", None) is not None:
            try:
                self._run_post_scan_triage(report, llm_context)
            except Exception as e:
                logger.warning("post-scan triage pass failed: %s", e)

        report.duration_seconds = time.perf_counter() - start
        report.compute_overall_score()
        report.compute_summary()

        if output_dir:
            await self._save_results(report, Path(output_dir))

        return report

    async def _establish_baseline_v3(self, adapter: Any) -> BaselineProfile:
        """Measure chat latency so DoS testers get a relative threshold.

        Sends a handful of benign prompts through the adapter's CHAT endpoint
        and records mean/p95/stddev. Returns an empty BaselineProfile on any
        failure (no CHAT endpoint, network error) — latency testers fall back
        to an absolute ceiling when ``samples == 0``.
        """
        import statistics
        from models.agent_profile import EndpointPurpose

        try:
            from core.preflight import _build_chat_payload
        except Exception:
            _build_chat_payload = None

        try:
            chat = adapter.find_endpoints_for(EndpointPurpose.CHAT)
        except Exception:
            chat = []
        if not chat:
            return BaselineProfile()

        endpoint = chat[0]
        query = "What is 2 + 2?"
        latencies: list[float] = []
        for _ in range(5):
            try:
                payload = _build_chat_payload(endpoint, query) if _build_chat_payload else {"question": query}
            except Exception:
                payload = {"question": query}
            try:
                resp = await adapter.invoke(endpoint, payload)
            except Exception as e:
                logger.debug(f"baseline probe failed: {e}")
                continue
            if int(getattr(resp, "status_code", 0) or 0) and 200 <= resp.status_code < 400:
                latencies.append(float(getattr(resp, "latency_ms", 0.0)))

        if not latencies:
            logger.info("Baseline: no successful probes; latency testers will use absolute ceiling")
            return BaselineProfile()

        latencies.sort()
        p95 = latencies[min(len(latencies) - 1, int(round(0.95 * (len(latencies) - 1))))]
        baseline = BaselineProfile(
            mean_ms=statistics.fmean(latencies),
            p95_ms=p95,
            stddev_ms=statistics.pstdev(latencies) if len(latencies) > 1 else 0.0,
            samples=len(latencies),
            baseline_query=query,
        )
        logger.info(
            f"Baseline established: mean={baseline.mean_ms:.0f}ms p95={baseline.p95_ms:.0f}ms "
            f"({baseline.samples} samples)"
        )
        return baseline

    @staticmethod
    def _has_structural_proof(evidence: Any) -> bool:
        """True when a VULN is backed by a hard, non-heuristic signal.

        Such findings are trusted as-is and skip the LLM judge: an explicit
        4xx/5xx status, an ``is_safe: false`` flag, or named security threats
        are deterministic — only the soft keyword/fuzzy verdicts need a judge.
        """
        if not isinstance(evidence, dict):
            return False
        if evidence.get("threats"):
            return True
        if evidence.get("is_safe") is False:
            return True
        status = evidence.get("status_code")
        if isinstance(status, int) and status >= 400:
            return True
        return False

    def _run_post_scan_triage(self, report: SecurityReport, llm_context: Any) -> None:
        """Send ambiguous findings to the LLM triager; update is_exploited/status."""
        from config.settings import TRIAGE_AMBIGUITY_BAND
        from llm.triage import FindingForTriage, is_ambiguous
        from models.enums import TestStatus

        triager = llm_context.triager
        # Build the queue. Two classes get judged:
        #   1. Ambiguous-confidence findings (fuzzy semantic detector).
        #   2. "Soft" VULNs — a FAILED verdict with no HARD structural proof
        #      (no 4xx/5xx, no is_safe=false, no explicit threats). These are
        #      keyword/heuristic decisions (e.g. EXT13 extraction, EXT05
        #      consistency) that are prone to false positives, so the LLM judge
        #      confirms or overturns each one. Findings backed by a real
        #      structural signal are trusted as-is and skip the judge.
        MAX_TRIAGE = 80
        queue: list[tuple[Any, FindingForTriage]] = []
        for cat in report.categories:
            for f in cat.findings:
                if f.status not in (TestStatus.PASSED, TestStatus.FAILED):
                    continue
                # Confidence lives in the detector evidence dict; default 1.0.
                conf = 1.0
                ev = getattr(f, "evidence", None) or {}
                if isinstance(ev, dict):
                    sc = ev.get("similarity_score")
                    if isinstance(sc, (int, float)):
                        conf = float(sc) / 100.0
                soft_vuln = (
                    f.status == TestStatus.FAILED
                    and not self._has_structural_proof(ev)
                )
                if not (is_ambiguous(conf, TRIAGE_AMBIGUITY_BAND) or soft_vuln):
                    continue
                if len(queue) >= MAX_TRIAGE:
                    logger.warning(
                        "post-scan triage: queue capped at %d; remaining soft "
                        "findings left as detector-decided", MAX_TRIAGE)
                    break
                queue.append((f, FindingForTriage(
                    finding_id=f.test_id or f.test_name or f"{cat.category.value}_{len(queue)}",
                    category=cat.category.value,
                    payload=str(getattr(f, "payload_sent", "") or "")[:1500],
                    response=str(getattr(f, "response_summary", "") or "")[:4000],
                    confidence=conf,
                )))
            if len(queue) >= MAX_TRIAGE:
                break

        if not queue:
            return

        logger.info("post-scan triage: %d findings sent to LLM judge", len(queue))
        try:
            verdicts = triager.triage_batch([q[1] for q in queue])
        except Exception as e:
            if e.__class__.__name__ == "BudgetExceededError":
                logger.warning("triage halted: %s", e)
                return
            raise

        # Apply verdicts back onto the report.
        verdict_by_id = {v.finding_id: v for v in verdicts}
        for finding, projection in queue:
            v = verdict_by_id.get(projection.finding_id)
            if v is None:
                continue
            if v.is_exploited and finding.status == TestStatus.PASSED:
                finding.status = TestStatus.FAILED
                finding.defense_held = False
            elif (not v.is_exploited) and finding.status == TestStatus.FAILED:
                finding.status = TestStatus.PASSED
                finding.defense_held = True
            if isinstance(finding.evidence, dict):
                finding.evidence["triage"] = {
                    "is_exploited": v.is_exploited,
                    "confidence": v.confidence,
                    "rationale": v.rationale,
                }
        # Recompute stats for any category we may have changed.
        for cat in report.categories:
            cat.compute_stats()

    def _import_testers(self) -> None:
        """Import all ASI and EXT tester modules to trigger @register_tester decorators."""
        import importlib
        _MODULE_MAP = {
            "tests_asi.asi01_goal_hijack":           "ASI01",
            "tests_asi.asi02_tool_misuse":           "ASI02",
            "tests_asi.asi03_privilege_abuse":       "ASI03",
            "tests_asi.asi04_supply_chain":          "ASI04",
            "tests_asi.asi05_code_execution":        "ASI05",
            "tests_asi.asi06_memory_poisoning":      "ASI06",
            "tests_asi.asi07_interagent_comms":      "ASI07",
            "tests_asi.asi08_cascading_failures":    "ASI08",
            "tests_asi.asi09_trust_exploitation":    "ASI09",
            "tests_asi.asi10_rogue_agents":          "ASI10",
            "tests_asi.ext01_log_injection":         "EXT01",
            "tests_asi.ext02_ltl_chain":             "EXT02",
            "tests_asi.ext03_consensus_spoofer":     "EXT03",
            "tests_asi.ext04_entropy_boundary":      "EXT04",
            "tests_asi.ext05_metamorphic_consistency": "EXT05",
            "tests_asi.ext06_z3_constraint_prober":  "EXT06",
            "tests_asi.ext07_goal_drift":            "EXT07",
            "tests_asi.ext08_sandbox_isolation":     "EXT08",
            "tests_asi.ext09_fol_axiom_enforcer":    "EXT09",
            "tests_asi.ext10_xpia_indirect_injection": "EXT10",
            "tests_asi.ext11_mcp_tool_poisoning":    "EXT11",
            "tests_asi.ext12_alignment_checker":     "EXT12",
            "tests_asi.ext13_model_extraction":      "EXT13",
            "tests_asi.ext14_data_poisoning":        "EXT14",
            "tests_asi.ext15_attribute_inference":   "EXT15",
            "tests_asi.ext16_cache_poisoning":       "EXT16",
            "tests_asi.ext17_delivery_hijack":       "EXT17",
        }
        for module_path, label in _MODULE_MAP.items():
            try:
                importlib.import_module(module_path)
            except ImportError as e:
                logger.debug(f"Could not import {label} ({module_path}): {e}")
            except Exception as e:
                logger.warning(f"Error importing {label} ({module_path}): {e}")
