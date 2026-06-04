"""
OWASP ASI Top 10 Security Testing Platform — CLI
=================================================
Commands:
  health    Pre-flight health check + baseline latency profiling
  register  Register an agent from a JSON config file
  scan      Run OWASP ASI security tests against a registered agent
  report    Re-generate reports from an existing results directory
"""

import asyncio
import json
import sys
import logging
from pathlib import Path

import click
from rich.console import Console

# Add Security_module root to sys.path so modules resolve correctly
_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# Load .env (ANTHROPIC_API_KEY, OPENAI_API_KEY, auth tokens, model overrides).
# Checks multiple candidate locations because users put .env in different
# places: repo root (Security_module/), current working dir, parent dir.
# Silent if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv  # type: ignore[import-not-found]
    _ENV_CANDIDATES = [
        _HERE / ".env",
        Path.cwd() / ".env",
        _HERE.parent / ".env",
    ]
    for _candidate in _ENV_CANDIDATES:
        if _candidate.exists() and _candidate.is_file():
            load_dotenv(_candidate, override=False)
except ImportError:
    pass

from config.agent_registry import load_agent_config, save_agent_config
from config.settings import RESULTS_DIR, LOGS_DIR, SAMPLE_CONFIGS_DIR
from models.enums import RiskCategory
from models.test_result import SecurityReport

console = Console(legacy_windows=True)

CATEGORY_CHOICES = [c.value for c in RiskCategory]


def _setup_logging(verbose: bool) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOGS_DIR / "cli.log", encoding="utf-8"),
        ],
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """OWASP ASI Top 10 Security Testing Platform for Agentic AI Systems."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ── health ───────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--config", "-c", required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to agent registration JSON",
)
@click.option("--no-baseline", is_flag=True, help="Skip baseline latency profiling")
@click.pass_context
def health(ctx: click.Context, config: str, no_baseline: bool) -> None:
    """Pre-flight health check and baseline latency profiling."""
    asyncio.run(_health_async(config, not no_baseline))


async def _health_async(config_path: str, run_baseline: bool) -> None:
    from core.http_client import AsyncHttpClient
    from core.health_checker import HealthChecker

    agent_config = load_agent_config(config_path)
    console.print(f"\n[bold]Health Check:[/bold] {agent_config.name}")
    console.print(f"Target: {agent_config.base_url}\n")

    client = AsyncHttpClient(
        base_url=agent_config.base_url,
        timeout_s=30,
        auth_headers=agent_config.auth_headers,
    )

    checker = HealthChecker(client, agent_config)
    status = await checker.check(run_baseline=run_baseline)
    await client.close()

    if status.healthy:
        console.print("[green]HEALTHY[/green] Agent is healthy")
    else:
        console.print("[red]FAILED[/red] Agent health check FAILED")
        sys.exit(1)

    console.print(f"\n[bold]Endpoints ({len(status.available_endpoints)} reachable):[/bold]")
    for ep in status.endpoints:
        icon = "[green]+[/green]" if ep.reachable else "[red]-[/red]"
        console.print(f"  {icon} {ep.path} ({ep.latency_ms:.0f}ms)")

    if run_baseline and status.baseline.samples > 0:
        b = status.baseline
        console.print(f"\n[bold]Baseline Profile ({b.samples} samples):[/bold]")
        console.print(f"  Mean:   {b.mean_ms:.0f}ms")
        console.print(f"  P95:    {b.p95_ms:.0f}ms")
        console.print(f"  StdDev: {b.stddev_ms:.0f}ms")
        console.print(f"  DoS threshold (P95 × 3.0): {b.p95_ms * 3.0:.0f}ms")


# ── register ─────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--config", "-c", required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to agent registration JSON",
)
@click.option(
    "--save-to", "-o",
    type=click.Path(dir_okay=False),
    help="Save validated config to this path (optional)",
)
def register(config: str, save_to: str | None) -> None:
    """Validate and register an agent from a JSON configuration file."""
    agent_config = load_agent_config(config)

    console.print(f"\n[green]OK[/green] Agent registered successfully")
    console.print(f"  Name:          {agent_config.name}")
    console.print(f"  ID:            {agent_config.agent_id}")
    console.print(f"  Type:          {agent_config.agent_type}")
    console.print(f"  Framework:     {agent_config.framework}")
    console.print(f"  Model:         {agent_config.model_backbone}")
    console.print(f"  Memory:        {agent_config.memory_type}")
    console.print(f"  Base URL:      {agent_config.base_url}")
    console.print(f"  Tools:         {len(agent_config.tools_manifest)}")
    console.print(f"  Sub-agents:    {len(agent_config.subagents)}")
    console.print(f"  Task suite:    {len(agent_config.task_suite)} tasks")
    console.print(f"  Max cost:      ${agent_config.max_cost_usd:.2f}")
    console.print(f"  SLA latency:   {agent_config.sla_latency_ms:,}ms")

    if save_to:
        out = save_agent_config(agent_config, Path(save_to))
        console.print(f"\n  Saved to: {out}")


# ── scan ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--config", "-c", required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to agent registration JSON",
)
@click.option(
    "--category", "-k",
    type=click.Choice(CATEGORY_CHOICES, case_sensitive=False),
    multiple=True,
    help="Run specific ASI category (can repeat). Default: all 10.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help=f"Output directory for results (default: {RESULTS_DIR})",
)
@click.option("--skip-baseline", is_flag=True, help="Skip baseline latency profiling")
@click.option("--skip-html", is_flag=True, help="Skip HTML report generation")
@click.option("--skip-sarif", is_flag=True, help="Skip SARIF report generation")
@click.option("--skip-junit", is_flag=True, help="Skip JUnit XML report generation")
@click.pass_context
def scan(
    ctx: click.Context,
    config: str,
    category: tuple[str, ...],
    output: str | None,
    skip_baseline: bool,
    skip_html: bool,
    skip_sarif: bool,
    skip_junit: bool,
) -> None:
    """Run OWASP ASI Top 10 security tests against an agent."""
    categories = [RiskCategory(c) for c in category] if category else None
    out_dir = Path(output) if output else RESULTS_DIR

    asyncio.run(_scan_async(
        config, categories, out_dir, skip_baseline, skip_html, skip_sarif, skip_junit
    ))


async def _scan_async(
    config_path: str,
    categories: list[RiskCategory] | None,
    out_dir: Path,
    skip_baseline: bool,
    skip_html: bool,
    skip_sarif: bool,
    skip_junit: bool,
) -> None:
    from core.test_runner import SecurityTestRunner
    from reporting.summary import print_summary
    from reporting.sarif_reporter import save_sarif_report
    from reporting.junit_reporter import save_junit_report
    from reporting.html_reporter import save_html_report

    agent_config = load_agent_config(config_path)

    console.print(f"\n[bold]OWASP ASI Security Scan[/bold]")
    console.print(f"Agent: [cyan]{agent_config.name}[/cyan]")
    console.print(f"Target: [cyan]{agent_config.base_url}[/cyan]")
    if categories:
        console.print(f"Categories: [cyan]{', '.join(c.value for c in categories)}[/cyan]")
    else:
        _ext_cats = sorted(c for c in CATEGORY_CHOICES if c.startswith("EXT"))
        _ext_range = f"EXT01–{_ext_cats[-1]}" if _ext_cats else "EXT01"
        console.print(f"Categories: [cyan]All {len(CATEGORY_CHOICES)} categories (ASI01–ASI10 + {_ext_range})[/cyan]")
    console.print("")

    runner = SecurityTestRunner(agent_config)
    report = await runner.run_all(
        categories=categories,
        skip_baseline=skip_baseline,
        output_dir=out_dir,
    )

    # Print console summary
    print_summary(report, console)

    # Find the run directory (most recent in out_dir)
    run_dirs = sorted(out_dir.glob("*_*/"), reverse=True)
    if run_dirs:
        run_dir = run_dirs[0]

        if not skip_sarif:
            save_sarif_report(report, run_dir / "report.sarif")
            console.print(f"[dim]SARIF: {run_dir / 'report.sarif'}[/dim]")

        if not skip_junit:
            save_junit_report(report, run_dir / "report.junit.xml")
            console.print(f"[dim]JUnit: {run_dir / 'report.junit.xml'}[/dim]")

        if not skip_html:
            save_html_report(report, run_dir / "report.html")
            console.print(f"[dim]HTML:  {run_dir / 'report.html'}[/dim]")

    # Exit with non-zero if critical vulnerabilities found
    critical_vulns = sum(
        1 for c in report.categories
        for f in c.findings
        if f.status.value == "FAILED" and f.severity.value == "CRITICAL"
    )
    if critical_vulns > 0:
        console.print(f"\n[bold red]!! {critical_vulns} CRITICAL vulnerabilities found[/bold red]")
        sys.exit(1)


# ── report ───────────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--results-dir", "-r", required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Path to existing results directory (contains report.json)",
)
@click.option("--format", "-f",
    type=click.Choice(["json", "sarif", "junit", "html", "all"]),
    default="all",
    help="Output format to generate",
)
def report(results_dir: str, format: str) -> None:
    """Re-generate reports from an existing results directory."""
    import json as json_lib
    from reporting.sarif_reporter import save_sarif_report
    from reporting.junit_reporter import save_junit_report
    from reporting.html_reporter import save_html_report
    from reporting.summary import print_summary

    run_dir = Path(results_dir)
    report_json = run_dir / "report.json"

    if not report_json.exists():
        console.print(f"[red]No report.json found in {run_dir}[/red]")
        sys.exit(1)

    with open(report_json, "r", encoding="utf-8") as f:
        data = json_lib.load(f)

    # Reconstruct minimal report for re-reporting
    console.print(f"[bold]Re-generating reports from:[/bold] {run_dir}")
    console.print(f"Agent: {data.get('agent_name', 'unknown')}")
    console.print(f"Score: {data.get('overall_risk_score', 0):.1f}/10.0")
    console.print(f"Summary: {data.get('summary', '')}")

    if format in ("sarif", "all"):
        # Build a minimal SecurityReport from JSON for SARIF
        _regen_reports(data, run_dir, format)

    console.print("[green]Done.[/green]")


def _regen_reports(data: dict, run_dir: Path, fmt: str) -> None:
    """Rebuild report objects from JSON for re-generation."""
    from reporting.sarif_reporter import save_sarif_report
    from reporting.junit_reporter import save_junit_report
    from reporting.html_reporter import save_html_report
    from models.test_result import SecurityReport, CategoryResult, Finding, BaselineProfile
    from models.enums import RiskCategory, Severity, TestStatus

    cats = []
    for c in data.get("categories", []):
        findings = []
        for f in c.get("findings", []):
            findings.append(Finding(
                test_id=f.get("test_id", ""),
                test_name=f.get("test_name", ""),
                category=RiskCategory(f.get("category", "ASI01")),
                status=TestStatus(f.get("status", "ERROR")),
                severity=Severity(f.get("severity", "INFO")),
                description=f.get("description", ""),
                payload_sent=f.get("payload_sent", {}),
                response_summary=f.get("response_summary", ""),
                defense_held=f.get("defense_held", True),
                evidence=f.get("evidence", {}),
                remediation=f.get("remediation", ""),
                latency_ms=f.get("latency_ms", 0),
                ttfb_ms=f.get("ttfb_ms", 0),
                cwe_id=f.get("cwe_id", ""),
                owasp_asi_id=f.get("owasp_asi_id", ""),
                owasp_llm_id=f.get("owasp_llm_id", ""),
                timestamp=f.get("timestamp", ""),
            ))
        cr = CategoryResult(
            category=RiskCategory(c.get("category", "ASI01")),
            category_name=c.get("category_name", ""),
            findings=findings,
            tests_run=c.get("tests_run", 0),
            tests_passed=c.get("tests_passed", 0),
            tests_failed=c.get("tests_failed", 0),
            tests_error=c.get("tests_error", 0),
            tests_skipped=c.get("tests_skipped", 0),
            risk_score=c.get("risk_score", 0.0),
            duration_seconds=c.get("duration_seconds", 0.0),
        )
        cats.append(cr)

    bl = data.get("baseline", {})
    report = SecurityReport(
        agent_name=data.get("agent_name", ""),
        agent_id=data.get("agent_id", ""),
        target_url=data.get("target_url", ""),
        scan_timestamp=data.get("scan_timestamp", ""),
        duration_seconds=data.get("duration_seconds", 0),
        baseline=BaselineProfile(
            mean_ms=bl.get("mean_ms", 0),
            p95_ms=bl.get("p95_ms", 0),
            stddev_ms=bl.get("stddev_ms", 0),
            samples=bl.get("samples", 0),
            baseline_query=bl.get("baseline_query", ""),
        ),
        categories=cats,
        overall_risk_score=data.get("overall_risk_score", 0),
        summary=data.get("summary", ""),
        recommendations=data.get("recommendations", []),
    )

    if fmt in ("sarif", "all"):
        save_sarif_report(report, run_dir / "report.sarif")
        console.print(f"  [green]OK[/green] SARIF: {run_dir / 'report.sarif'}")
    if fmt in ("junit", "all"):
        save_junit_report(report, run_dir / "report.junit.xml")
        console.print(f"  [green]OK[/green] JUnit: {run_dir / 'report.junit.xml'}")
    if fmt in ("html", "all"):
        save_html_report(report, run_dir / "report.html")
        console.print(f"  [green]OK[/green] HTML:  {run_dir / 'report.html'}")


# ─────────────────────────────────────────────────────────────────────────
# v3 commands: discover / plan / scan --dry-run
# These operate on the generic AgentProfile model, not legacy AgentConfig.
# ─────────────────────────────────────────────────────────────────────────


_RISK_TIER_CHOICES = ["low", "medium", "high", "critical"]


@cli.command("discover")
@click.option("--url", "base_url", required=True, help="Agent base URL (e.g. http://localhost:9100)")
@click.option("--openapi-url", default=None, help="Direct URL to an OpenAPI/Swagger spec. If omitted, well-known paths are probed.")
@click.option("--auth-env", default=None, metavar="VAR", help="Name of env var holding the auth token (NOT the token value itself)")
@click.option("--allow-internal", is_flag=True, help="Allow RFC1918 / loopback / metadata-service targets (lab use only)")
@click.option("--risk-tier", type=click.Choice(_RISK_TIER_CHOICES), default=None, help="Override the inferred risk tier")
@click.option("--name", default=None, help="Override the inferred agent name")
@click.option("--out", "-o", required=True, type=click.Path(dir_okay=False), help="Where to write the resulting profile JSON")
@click.option("--dry-run", is_flag=True, help="Print what would be fetched without making network calls")
def discover_cmd(
    base_url: str,
    openapi_url: str | None,
    auth_env: str | None,
    allow_internal: bool,
    risk_tier: str | None,
    name: str | None,
    out: str,
    dry_run: bool,
) -> None:
    """Build an AgentProfile from an OpenAPI spec or well-known probing."""
    from discovery.openapi_parser import parse_openapi_url
    from discovery.well_known_prober import probe_well_known
    from models.agent_profile import AuthConfig, AuthScheme

    if dry_run:
        console.print("[bold yellow]DRY-RUN[/bold yellow] would fetch:")
        console.print(f"  spec_url: {openapi_url or '(probe well-known under ' + base_url + ')'}")
        console.print(f"  allow_internal: {allow_internal}")
        console.print(f"  output: {out}")
        return

    spec_url = openapi_url
    if not spec_url:
        console.print(f"[dim]probing well-known paths under {base_url}...[/dim]")
        spec_url = probe_well_known(base_url, allow_internal=allow_internal)
        if not spec_url:
            console.print(
                "[red]ERROR[/red] no OpenAPI spec found via well-known probing. "
                "Pass --openapi-url explicitly or use --config for legacy manifests."
            )
            sys.exit(2)
        console.print(f"[dim]found spec at {spec_url}[/dim]")

    profile = parse_openapi_url(spec_url, name=name, allow_internal=allow_internal)

    if auth_env:
        profile.auth = AuthConfig(
            scheme=profile.auth.scheme if profile.auth.scheme != AuthScheme.NONE else AuthScheme.BEARER,
            token_env_var=auth_env,
            header_name=profile.auth.header_name,
            header_prefix=profile.auth.header_prefix,
        )

    if risk_tier:
        profile.risk_tier = risk_tier  # type: ignore[assignment]
        profile.risk_tier_source = "user"

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")

    console.print(f"\n[green]OK[/green] AgentProfile written to {out_path}")
    console.print(f"  Name:           {profile.name}")
    console.print(f"  Base URL:       {profile.base_url}")
    console.print(f"  Transport:      {profile.transport.value}")
    console.print(f"  Endpoints:      {len(profile.endpoints)}")
    console.print(f"  Tools:          {len(profile.tools)}")
    console.print(f"  Capabilities:   {', '.join(c.value for c in profile.inferred_capabilities) or '(none)'}")
    console.print(f"  Risk tier:      {profile.risk_tier} ({profile.risk_tier_source})")
    console.print(f"  Auth:           {profile.auth.scheme.value}" + (f" (env var: {profile.auth.token_env_var})" if profile.auth.token_env_var else ""))


@cli.command("plan")
@click.option("--profile", "-p", required=True, type=click.Path(exists=True, dir_okay=False), help="AgentProfile JSON from `discover`")
@click.option("--llm", is_flag=True, help="Use LLM planner (Phase 6) — currently a stub")
@click.option("--max-payloads", type=int, default=20, show_default=True)
@click.option("--out", "-o", required=True, type=click.Path(dir_okay=False), help="Where to write the resulting plan JSON")
def plan_cmd(profile: str, llm: bool, max_payloads: int, out: str) -> None:
    """Build a TestPlan from an AgentProfile."""
    from core.stub_planner import build_stub_plan
    from models.agent_profile import AgentProfile

    p = AgentProfile.model_validate_json(Path(profile).read_text(encoding="utf-8-sig"))

    if llm:
        try:
            from llm.context import LLMContext
            from llm.client import LLMUnavailableError
            ctx = LLMContext.enable()  # auto-picks anthropic or openai based on env
            plan = ctx.planner.plan(p, max_payloads_default=max_payloads)
            console.print(
                f"[dim]LLM planner used (provider={ctx.provider}, "
                f"{ctx.budget.calls_made} call(s), ${ctx.budget.spend_usd:.4f})[/dim]"
            )
        except LLMUnavailableError as e:
            console.print(f"[yellow]LLM unavailable ({e}); falling back to stub planner.[/yellow]")
            plan = build_stub_plan(p, max_payloads=max_payloads)
    else:
        plan = build_stub_plan(p, max_payloads=max_payloads)

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")

    included = plan.included_categories()
    skipped = [c for c in plan.categories if not c.include]

    console.print(f"\n[green]OK[/green] TestPlan written to {out_path}")
    console.print(f"  Planner:        {plan.planner}")
    console.print(f"  Categories run: {len(included)} / {len(plan.categories)}")
    console.print(f"  Skipped:        {len(skipped)}")
    console.print(f"  Est. LLM calls: {plan.cost_estimate.projected_llm_calls}")
    console.print(f"  Est. cost:      ${plan.cost_estimate.projected_usd:.4f}")
    if skipped:
        console.print("\n[dim]Skipped categories:[/dim]")
        for c in skipped:
            console.print(f"  [dim]- {c.category.value}: {c.skip_reason}[/dim]")


@cli.command("preflight")
@click.option("--profile", "-p", required=True, type=click.Path(exists=True, dir_okay=False), help="AgentProfile JSON")
@click.option("--allow-internal", is_flag=True, help="Allow RFC1918 / loopback / metadata targets (lab use only)")
@click.option("--preflight-latency", is_flag=True, help="Include baseline_latency check (~2 chat round trips)")
@click.option("--preflight-warn-only", is_flag=True, help="Downgrade FAILs to WARNs; exit 0 on WARN")
@click.option("--yes", is_flag=True, help="Bypass all interactive prompts (CI/automation)")
def preflight_cmd(
    profile: str,
    allow_internal: bool,
    preflight_latency: bool,
    preflight_warn_only: bool,
    yes: bool,
) -> None:
    """Run preflight verification against an AgentProfile.

    Exits 0 on GREEN, 1 on WARN (or declined consent), 2 on HARD-STOP.
    """
    from core.preflight import (
        Preflight,
        PreflightOptions,
        render_console,
        confirm_proceed_on_warn,
    )
    from core.ssrf_guard import assert_url_safe, SSRFBlockedError
    from core.target_adapter import make_adapter
    from models.agent_profile import AgentProfile

    p = AgentProfile.model_validate_json(Path(profile).read_text(encoding="utf-8-sig"))

    try:
        assert_url_safe(str(p.base_url), allow_internal=allow_internal)
    except SSRFBlockedError as e:
        console.print(f"[red]SSRF guard blocked target:[/red] {e}")
        sys.exit(2)

    async def _run() -> int:
        adapter = make_adapter(p)
        try:
            pf = Preflight(
                p,
                adapter,
                PreflightOptions(
                    include_latency=preflight_latency,
                    warn_only=preflight_warn_only,
                    yes=yes,
                ),
            )
            result = await pf.run()
            render_console(result, console)
            if result.overall == "hard_stop":
                return 2
            if result.overall == "warn":
                if preflight_warn_only:
                    return 0
                if confirm_proceed_on_warn(result, yes=yes):
                    return 0
                return 1
            return 0
        finally:
            try:
                await adapter.close()
            except Exception:
                pass

    rc = asyncio.run(_run())
    sys.exit(rc)


@cli.command("scan-v3")
@click.option("--profile", "-p", required=True, type=click.Path(exists=True, dir_okay=False), help="AgentProfile JSON")
@click.option("--plan", "plan_path", type=click.Path(exists=True, dir_okay=False), default=None, help="TestPlan JSON (built on the fly if omitted)")
@click.option("--dry-run", is_flag=True, help="Print every payload that WOULD be sent; make zero network calls")
@click.option("--category", "-k", type=click.Choice(CATEGORY_CHOICES, case_sensitive=False), multiple=True)
@click.option("--llm", is_flag=True, help="Enable LLM payload synthesis + triage (Phase 6 — currently no-op)")
@click.option("--max-llm-calls", type=int, default=None)
@click.option("--max-llm-spend-usd", type=float, default=None)
@click.option("--rate-limit-rpm", type=int, default=None)
@click.option("--allow-internal", is_flag=True, help="Allow RFC1918 / loopback targets (lab use only)")
@click.option("--skip-preflight", is_flag=True, help="Bypass preflight verification entirely")
@click.option("--preflight-warn-only", is_flag=True, help="Downgrade preflight FAILs to WARNs; exit 0 on WARN")
@click.option("--preflight-latency", is_flag=True, help="Include baseline_latency check (~2 chat round trips)")
@click.option("--fingerprint", is_flag=True, help="Run passive agent fingerprinting after preflight")
@click.option("--fingerprint-aggressive", is_flag=True, help="Add aggressive probes (system-prompt extraction, etc) — requires consent")
@click.option("--fingerprint-budget", type=float, default=0.05, show_default=True, help="USD cap for fingerprint LLM cost")
@click.option("--yes", is_flag=True, help="Bypass all interactive prompts (CI/automation)")
def scan_v3_cmd(
    profile: str,
    plan_path: str | None,
    dry_run: bool,
    category: tuple[str, ...],
    llm: bool,
    max_llm_calls: int | None,
    max_llm_spend_usd: float | None,
    rate_limit_rpm: int | None,
    allow_internal: bool,
    skip_preflight: bool,
    preflight_warn_only: bool,
    preflight_latency: bool,
    fingerprint: bool,
    fingerprint_aggressive: bool,
    fingerprint_budget: float,
    yes: bool,
) -> None:
    """v3 generic scan. Currently supports --dry-run; live execution lands in Phase 4."""
    from core.stub_planner import build_stub_plan
    from models.agent_profile import AgentProfile
    from models.enums import RiskCategory
    from models.test_plan import TestPlan

    p = AgentProfile.model_validate_json(Path(profile).read_text(encoding="utf-8-sig"))

    if plan_path:
        plan = TestPlan.model_validate_json(Path(plan_path).read_text(encoding="utf-8-sig"))
    else:
        plan = build_stub_plan(p)

    # --category filter overlays the loaded plan: only the named categories run,
    # all others get SKIPPED_CATEGORY_FILTER as their reason.
    if category:
        chosen = {RiskCategory(c) for c in category}
        for c in plan.categories:
            if c.category not in chosen:
                c.include = False
                c.skip_reason = "SKIPPED_CATEGORY_FILTER"

    if not dry_run:
        # SSRF gate — single owner for live scans. Preflight does NOT re-call.
        from core.ssrf_guard import assert_url_safe, SSRFBlockedError
        try:
            assert_url_safe(str(p.base_url), allow_internal=allow_internal)
        except SSRFBlockedError as e:
            console.print(f"[red]SSRF guard blocked target:[/red] {e}")
            sys.exit(2)

        # v3 live execution path (Phase 5).
        from core.target_adapter import make_adapter
        from core.test_runner import SecurityTestRunner
        from config.settings import RESULTS_DIR

        cli_filter = {RiskCategory(c) for c in category} if category else None

        llm_context = None
        if llm:
            try:
                from llm.context import LLMContext
                llm_context = LLMContext.enable(
                    max_calls=max_llm_calls,
                    max_spend_usd=max_llm_spend_usd,
                )
                console.print(
                    f"[dim]LLM enabled — provider={llm_context.provider}, "
                    f"caps: calls={max_llm_calls or '∞'}, spend=${max_llm_spend_usd or '∞'}[/dim]"
                )
            except Exception as e:
                console.print(f"[yellow]LLM unavailable ({e}); proceeding without LLM.[/yellow]")
                llm_context = None

        async def _run() -> None:
            adapter = make_adapter(p)

            # Preflight (Part 1) — ON by default.
            if not skip_preflight:
                from core.preflight import (
                    Preflight,
                    PreflightOptions,
                    PreflightFailure,
                    render_console,
                    confirm_proceed_on_warn,
                )
                pf = Preflight(
                    p,
                    adapter,
                    PreflightOptions(
                        include_latency=preflight_latency,
                        warn_only=preflight_warn_only,
                        yes=yes,
                    ),
                )
                pf_result = await pf.run()
                render_console(pf_result, console)
                if pf_result.overall == "hard_stop":
                    await adapter.close()
                    sys.exit(2)
                if pf_result.overall == "warn" and not preflight_warn_only:
                    if not confirm_proceed_on_warn(pf_result, yes=yes):
                        console.print("[yellow]Preflight warnings not acknowledged; aborting.[/yellow]")
                        await adapter.close()
                        sys.exit(1)

            # Fingerprint (Part 2) — opt-in.
            if fingerprint or fingerprint_aggressive:
                from core.agent_fingerprinter import (
                    AgentFingerprinter,
                    FingerprintOptions,
                    confirm_aggressive_consent,
                )
                if fingerprint_aggressive:
                    if not confirm_aggressive_consent(yes=yes):
                        console.print("[yellow]Aggressive fingerprint consent declined; aborting.[/yellow]")
                        await adapter.close()
                        sys.exit(1)
                fp_opts = FingerprintOptions(
                    aggressive=fingerprint_aggressive,
                    budget_usd=fingerprint_budget,
                )
                fp = AgentFingerprinter(p, adapter, fp_opts, llm_context=llm_context)
                evidence = await fp.fingerprint()
                # Merge into profile (live mutation; saved separately too)
                p.fingerprint_evidence = evidence
                p.detected_model_family = fp.detected_model_family
                p.response_shape = fp.response_shape
                p.guardrail_strength = fp.guardrail_strength
                p.detected_tools = fp.detected_tools
                p.confirmed_capabilities = fp.confirmed_capabilities
                # Persist enriched profile
                try:
                    enriched_path = Path(profile).with_suffix(".enriched.json")
                    enriched_path.write_text(p.model_dump_json(indent=2), encoding="utf-8")
                    console.print(f"[dim]Enriched profile written to {enriched_path}[/dim]")
                except Exception as e:
                    console.print(f"[yellow]Could not save enriched profile: {e}[/yellow]")

            runner = SecurityTestRunner(config=None)
            report = await runner.run_with_profile(
                profile=p,
                plan=plan,
                adapter=adapter,
                output_dir=RESULTS_DIR,
                cli_filter=cli_filter,
                llm_context=llm_context,
            )
            if llm_context is not None:
                console.print(
                    f"[dim]LLM usage: {llm_context.budget.calls_made} call(s), "
                    f"${llm_context.budget.spend_usd:.4f}[/dim]"
                )
            from reporting.summary import print_summary
            print_summary(report, console)

            # Generate auxiliary reports (SARIF/JUnit/HTML).
            run_dirs = sorted(RESULTS_DIR.glob("*_*/"), reverse=True)
            if run_dirs:
                run_dir = run_dirs[0]
                from reporting.sarif_reporter import save_sarif_report
                from reporting.junit_reporter import save_junit_report
                from reporting.html_reporter import save_html_report
                save_sarif_report(report, run_dir / "report.sarif")
                save_junit_report(report, run_dir / "report.junit.xml")
                save_html_report(report, run_dir / "report.html", profile=p)
                console.print(f"[dim]Reports written to {run_dir}[/dim]")

            critical = sum(
                1 for c in report.categories
                for f in c.findings
                if f.status.value == "FAILED" and f.severity.value == "CRITICAL"
            )
            if critical:
                console.print(f"\n[bold red]!! {critical} CRITICAL vulnerabilities found[/bold red]")
                sys.exit(1)

        asyncio.run(_run())
        return

    # Dry-run path: adapter-INDEPENDENT. We do not instantiate RestAgentAdapter.
    console.print(f"\n[bold yellow]DRY-RUN[/bold yellow] {p.name} @ {p.base_url}\n")
    included = plan.included_categories()
    console.print(f"Would run [cyan]{len(included)}[/cyan] categories with up to "
                  f"[cyan]{sum(c.max_payloads for c in included)}[/cyan] total seed payloads.\n")

    chat_endpoints = p.endpoints_for(__import__('models.agent_profile', fromlist=['EndpointPurpose']).EndpointPurpose.CHAT)
    if chat_endpoints:
        sample_path = chat_endpoints[0].path
    elif p.endpoints:
        sample_path = p.endpoints[0].path
    else:
        sample_path = "(no endpoints)"

    for cp in included:
        console.print(f"  [bold]{cp.category.value}[/bold] prio={cp.priority} payloads={cp.max_payloads}")
        console.print(f"    -> POST {p.base_url}{sample_path}  (sample, real adapter picks per-tester)")
    skipped = [c for c in plan.categories if not c.include]
    if skipped:
        console.print(f"\n[dim]{len(skipped)} categories skipped:[/dim]")
        for c in skipped:
            console.print(f"  [dim]- {c.category.value}: {c.skip_reason}[/dim]")
    console.print(f"\n[bold]Cost estimate:[/bold] {plan.cost_estimate.projected_llm_calls} LLM calls, "
                  f"${plan.cost_estimate.projected_usd:.4f}")
    if llm and not (max_llm_calls or max_llm_spend_usd):
        console.print("[dim]Tip: with --llm, also set --max-llm-spend-usd to cap budget.[/dim]")


if __name__ == "__main__":
    cli()
