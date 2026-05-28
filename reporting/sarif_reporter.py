"""
SARIF v2.1.0 reporter for CI/CD integration.
Compatible with GitHub Code Scanning, GitLab SAST, Azure DevOps.
"""

import json
import logging
from pathlib import Path
from models.enums import Severity, TestStatus
from models.test_result import SecurityReport, Finding

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _build_rules(report: SecurityReport) -> list[dict]:
    """Build SARIF rule definitions from ASI categories."""
    rules = []
    seen = set()
    for cat in report.categories:
        for finding in cat.findings:
            rule_id = finding.owasp_asi_id
            if rule_id in seen:
                continue
            seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": cat.category_name.replace(" ", ""),
                "shortDescription": {"text": cat.category_name},
                "fullDescription": {
                    "text": f"OWASP ASI {rule_id}: {cat.category_name}"
                },
                "helpUri": f"https://genai.owasp.org/agentic-ai-threats-and-mitigations/",
                "properties": {
                    "tags": ["security", "owasp", "agentic-ai", rule_id.lower()],
                },
            })
    return rules


def _build_results(report: SecurityReport) -> list[dict]:
    """Build SARIF results from findings."""
    results = []
    for cat in report.categories:
        for finding in cat.findings:
            if finding.status == TestStatus.PASSED:
                continue  # Only report vulnerabilities

            result = {
                "ruleId": finding.owasp_asi_id,
                "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
                "message": {
                    "text": (
                        f"{finding.description}\n\n"
                        f"Test: {finding.test_name}\n"
                        f"CWE: {finding.cwe_id}\n"
                        f"OWASP LLM: {finding.owasp_llm_id}\n"
                        f"Remediation: {finding.remediation}"
                    ),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report.target_url,
                            "uriBaseId": "AGENT_ENDPOINT",
                        },
                    },
                    "logicalLocations": [{
                        "name": finding.test_name,
                        "kind": "endpoint",
                    }],
                }],
                "properties": {
                    "severity": finding.severity.value,
                    "defense_held": finding.defense_held,
                    "latency_ms": finding.latency_ms,
                    "ttfb_ms": finding.ttfb_ms,
                    "cwe_id": finding.cwe_id,
                    "owasp_llm_id": finding.owasp_llm_id,
                    "timestamp": finding.timestamp,
                },
            }

            if finding.evidence:
                result["properties"]["evidence"] = finding.evidence

            results.append(result)

    return results


def save_sarif_report(report: SecurityReport, output_path: Path) -> Path:
    """Generate SARIF v2.1.0 report."""
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OWASP-ASI-Security-Tester",
                    "version": "1.0.0",
                    "informationUri": "https://genai.owasp.org/",
                    "rules": _build_rules(report),
                },
            },
            "results": _build_results(report),
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": report.scan_timestamp,
                "properties": {
                    "agent_name": report.agent_name,
                    "agent_id": report.agent_id,
                    "target_url": report.target_url,
                    "overall_risk_score": report.overall_risk_score,
                    "duration_seconds": report.duration_seconds,
                },
            }],
        }],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
    logger.info(f"SARIF report saved: {output_path}")
    return output_path
