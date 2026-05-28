"""Rich console summary output for security assessment results."""

import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from models.enums import Severity, TestStatus
from models.test_result import SecurityReport

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.INFO: "blue",
}

STATUS_COLORS = {
    TestStatus.PASSED: "green",
    TestStatus.FAILED: "bright_red",
    TestStatus.ERROR: "yellow",
    TestStatus.SKIPPED: "dim",
    TestStatus.SKIPPED_CAPABILITY: "dim",
    TestStatus.SKIPPED_TRANSPORT: "dim",
    TestStatus.SKIPPED_CATEGORY_FILTER: "dim",
    TestStatus.SKIPPED_BUDGET: "magenta",
    TestStatus.SKIPPED_UNCLASSIFIED: "yellow",
    TestStatus.TARGET_RATE_LIMITED: "yellow",
}


def print_summary(report: SecurityReport, console: Console | None = None) -> None:
    """Print rich console summary of security assessment."""
    console = console or Console(legacy_windows=True)

    # Header
    score = report.overall_risk_score
    if score >= 7.0:
        score_color = "bright_red"
        risk_level = "CRITICAL"
    elif score >= 4.0:
        score_color = "red"
        risk_level = "HIGH"
    elif score >= 2.0:
        score_color = "yellow"
        risk_level = "MEDIUM"
    elif score > 0:
        score_color = "green"
        risk_level = "LOW"
    else:
        score_color = "bright_green"
        risk_level = "NONE"

    header = Text()
    header.append("OWASP ASI Top 10 Security Assessment\n", style="bold")
    header.append(f"Agent: {report.agent_name}\n")
    header.append(f"Target: {report.target_url}\n")
    header.append(f"Duration: {report.duration_seconds:.1f}s\n")
    header.append(f"Overall Risk: ", style="bold")
    header.append(f"{score:.1f}/10.0 ({risk_level})", style=f"bold {score_color}")

    console.print(Panel(header, title="Security Assessment", border_style=score_color))

    # Category summary table
    table = Table(title="Category Results", show_lines=True)
    table.add_column("Category", style="bold", width=40)
    table.add_column("Tests", justify="center", width=8)
    table.add_column("Held", justify="center", style="green", width=8)
    table.add_column("Vuln", justify="center", style="bright_red", width=8)
    table.add_column("Error", justify="center", style="yellow", width=8)
    table.add_column("Risk", justify="center", width=8)

    for cat in report.categories:
        risk_style = "bright_red" if cat.risk_score >= 7 else "red" if cat.risk_score >= 4 else "yellow" if cat.risk_score >= 2 else "green"
        table.add_row(
            f"{cat.category.value}: {cat.category_name}",
            str(cat.tests_run),
            str(cat.tests_passed),
            str(cat.tests_failed),
            str(cat.tests_error),
            Text(f"{cat.risk_score:.1f}", style=risk_style),
        )

    console.print(table)

    # Vulnerability findings
    vuln_count = sum(c.tests_failed for c in report.categories)
    if vuln_count > 0:
        vuln_table = Table(title=f"Vulnerabilities Found ({vuln_count})", show_lines=True)
        vuln_table.add_column("Category", width=8)
        vuln_table.add_column("Test", width=30)
        vuln_table.add_column("Severity", width=10)
        vuln_table.add_column("CWE", width=10)
        vuln_table.add_column("Description", width=60)

        for cat in report.categories:
            for f in cat.findings:
                if f.status == TestStatus.FAILED:
                    sev_color = SEVERITY_COLORS.get(f.severity, "white")
                    vuln_table.add_row(
                        f.owasp_asi_id,
                        f.test_name,
                        Text(f.severity.value, style=sev_color),
                        f.cwe_id,
                        f.description[:60],
                    )

        console.print(vuln_table)

    # Recommendations
    if report.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  [yellow]>[/yellow] {rec}")

    # Baseline info
    if report.baseline.samples > 0:
        console.print(f"\n[dim]Baseline: mean={report.baseline.mean_ms:.0f}ms "
                      f"p95={report.baseline.p95_ms:.0f}ms "
                      f"({report.baseline.samples} samples)[/dim]")

    console.print(f"\n[dim]Report saved to results/ directory[/dim]")
