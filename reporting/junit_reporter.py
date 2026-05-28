"""
JUnit XML reporter for CI/CD pipeline integration.
Compatible with Jenkins, CircleCI, GitHub Actions test reporting.
"""

import logging
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree, indent
from models.enums import TestStatus
from models.test_result import SecurityReport

logger = logging.getLogger(__name__)


def save_junit_report(report: SecurityReport, output_path: Path) -> Path:
    """Generate JUnit XML report."""
    testsuites = Element("testsuites", {
        "name": f"OWASP ASI Security Assessment - {report.agent_name}",
        "tests": str(sum(c.tests_run for c in report.categories)),
        "failures": str(sum(c.tests_failed for c in report.categories)),
        "errors": str(sum(c.tests_error for c in report.categories)),
        "time": f"{report.duration_seconds:.2f}",
        "timestamp": report.scan_timestamp,
    })

    for cat in report.categories:
        suite = SubElement(testsuites, "testsuite", {
            "name": f"{cat.category.value}: {cat.category_name}",
            "tests": str(cat.tests_run),
            "failures": str(cat.tests_failed),
            "errors": str(cat.tests_error),
            "skipped": str(cat.tests_skipped),
            "time": f"{cat.duration_seconds:.2f}",
        })

        for finding in cat.findings:
            testcase = SubElement(suite, "testcase", {
                "name": finding.test_name,
                "classname": f"asi.{cat.category.value.lower()}.{finding.test_name}",
                "time": f"{finding.latency_ms / 1000:.3f}",
            })

            if finding.status == TestStatus.FAILED:
                failure = SubElement(testcase, "failure", {
                    "message": finding.description,
                    "type": f"{finding.severity.value}_VULNERABILITY",
                })
                failure.text = (
                    f"Severity: {finding.severity.value}\n"
                    f"CWE: {finding.cwe_id}\n"
                    f"OWASP ASI: {finding.owasp_asi_id}\n"
                    f"OWASP LLM: {finding.owasp_llm_id}\n"
                    f"Remediation: {finding.remediation}\n"
                    f"Evidence: {finding.evidence}\n"
                    f"Payload: {finding.payload_sent}\n"
                    f"Response: {finding.response_summary[:300]}"
                )

            elif finding.status == TestStatus.ERROR:
                error = SubElement(testcase, "error", {
                    "message": finding.description,
                    "type": "TEST_ERROR",
                })
                error.text = finding.response_summary[:500]

            elif finding.status in (
                TestStatus.SKIPPED,
                TestStatus.SKIPPED_CAPABILITY,
                TestStatus.SKIPPED_TRANSPORT,
                TestStatus.SKIPPED_CATEGORY_FILTER,
                TestStatus.SKIPPED_BUDGET,
                TestStatus.SKIPPED_UNCLASSIFIED,
                TestStatus.TARGET_RATE_LIMITED,
            ):
                SubElement(testcase, "skipped", {
                    "message": f"[{finding.status.value}] {finding.description}",
                })

            # Add system-out with details for all test cases
            system_out = SubElement(testcase, "system-out")
            system_out.text = (
                f"Defense Held: {finding.defense_held}\n"
                f"Latency: {finding.latency_ms:.0f}ms\n"
                f"TTFB: {finding.ttfb_ms:.0f}ms"
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    tree = ElementTree(testsuites)
    indent(tree, space="  ")
    tree.write(output_path, encoding="unicode", xml_declaration=True)
    logger.info(f"JUnit report saved: {output_path}")
    return output_path
