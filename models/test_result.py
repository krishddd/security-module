"""Data models for security test findings, category results, and full reports."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from models.enums import RiskCategory, Severity, TestStatus


@dataclass
class Finding:
    """A single security test finding."""
    test_id: str
    test_name: str
    category: RiskCategory
    status: TestStatus
    severity: Severity
    description: str
    payload_sent: dict[str, Any]
    response_summary: str
    defense_held: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    latency_ms: float = 0.0
    ttfb_ms: float = 0.0
    cwe_id: str = ""
    owasp_asi_id: str = ""
    owasp_llm_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "category": self.category.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "description": self.description,
            "payload_sent": self.payload_sent,
            "response_summary": self.response_summary,
            "defense_held": self.defense_held,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "latency_ms": self.latency_ms,
            "ttfb_ms": self.ttfb_ms,
            "cwe_id": self.cwe_id,
            "owasp_asi_id": self.owasp_asi_id,
            "owasp_llm_id": self.owasp_llm_id,
            "timestamp": self.timestamp,
        }


@dataclass
class CategoryResult:
    """Aggregated results for one ASI category."""
    category: RiskCategory
    category_name: str
    findings: list[Finding] = field(default_factory=list)
    tests_run: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    tests_error: int = 0
    tests_skipped: int = 0
    risk_score: float = 0.0
    duration_seconds: float = 0.0

    def compute_stats(self) -> None:
        self.tests_run = len(self.findings)
        self.tests_passed = sum(1 for f in self.findings if f.status == TestStatus.PASSED)
        self.tests_failed = sum(1 for f in self.findings if f.status == TestStatus.FAILED)
        self.tests_error = sum(1 for f in self.findings if f.status == TestStatus.ERROR)
        # All SKIPPED_* sub-statuses count as skipped for scoring purposes.
        from .enums import SKIPPED_STATUSES
        self.tests_skipped = sum(1 for f in self.findings if f.status in SKIPPED_STATUSES)

        if self.tests_run > 0:
            severity_weight = self.category.default_severity.weight
            self.risk_score = (self.tests_failed / self.tests_run) * severity_weight
        else:
            self.risk_score = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "category_name": self.category_name,
            "tests_run": self.tests_run,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "tests_error": self.tests_error,
            "tests_skipped": self.tests_skipped,
            "risk_score": round(self.risk_score, 2),
            "duration_seconds": round(self.duration_seconds, 2),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class BaselineProfile:
    """Latency baseline established during health check."""
    mean_ms: float = 0.0
    p95_ms: float = 0.0
    stddev_ms: float = 0.0
    samples: int = 0
    baseline_query: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mean_ms": round(self.mean_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "stddev_ms": round(self.stddev_ms, 2),
            "samples": self.samples,
            "baseline_query": self.baseline_query,
        }


@dataclass
class SecurityReport:
    """Full security assessment report."""
    agent_name: str
    agent_id: str
    target_url: str
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_seconds: float = 0.0
    baseline: BaselineProfile = field(default_factory=BaselineProfile)
    categories: list[CategoryResult] = field(default_factory=list)
    overall_risk_score: float = 0.0
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)

    def compute_overall_score(self) -> None:
        if not self.categories:
            self.overall_risk_score = 0.0
            return
        total_weight = sum(c.category.default_severity.weight for c in self.categories)
        weighted_sum = sum(
            c.risk_score * c.category.default_severity.weight for c in self.categories
        )
        self.overall_risk_score = weighted_sum / total_weight if total_weight > 0 else 0.0

    def compute_summary(self) -> None:
        total_tests = sum(c.tests_run for c in self.categories)
        total_failed = sum(c.tests_failed for c in self.categories)
        total_passed = sum(c.tests_passed for c in self.categories)

        if self.overall_risk_score >= 7.0:
            risk_level = "CRITICAL"
        elif self.overall_risk_score >= 4.0:
            risk_level = "HIGH"
        elif self.overall_risk_score >= 2.0:
            risk_level = "MEDIUM"
        elif self.overall_risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "NONE"

        self.summary = (
            f"OWASP ASI Security Assessment: {risk_level} risk. "
            f"{total_tests} tests executed, {total_passed} defenses held, "
            f"{total_failed} vulnerabilities found. "
            f"Overall risk score: {self.overall_risk_score:.1f}/10.0"
        )

        self.recommendations = []
        for cat in self.categories:
            if cat.tests_failed > 0:
                self.recommendations.append(
                    f"[{cat.category.value}] {cat.category_name}: "
                    f"{cat.tests_failed} vulnerability(ies) found — "
                    f"review findings and apply OWASP ASI mitigations."
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "target_url": self.target_url,
            "scan_timestamp": self.scan_timestamp,
            "duration_seconds": round(self.duration_seconds, 2),
            "baseline": self.baseline.to_dict(),
            "overall_risk_score": round(self.overall_risk_score, 2),
            "summary": self.summary,
            "recommendations": self.recommendations,
            "categories": [c.to_dict() for c in self.categories],
        }
