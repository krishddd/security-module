"""Enumerations and CWE/OWASP mappings for the security testing platform."""

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 2.0,
            Severity.INFO: 1.0,
        }[self]


class TestStatus(str, Enum):
    PASSED = "PASSED"      # Defense held — attack was blocked
    FAILED = "FAILED"      # Vulnerability found — attack got through
    ERROR = "ERROR"        # Test could not complete (infra issue)
    SKIPPED = "SKIPPED"    # Test skipped (generic precondition not met)
    # v3 sub-statuses (still treated as "skipped" by scoring, but reporters
    # render the reason so users know WHY a tester didn't run).
    SKIPPED_CAPABILITY = "SKIPPED_CAPABILITY"          # Profile lacks required AgentCapability
    SKIPPED_TRANSPORT = "SKIPPED_TRANSPORT"            # Adapter for this transport not implemented
    SKIPPED_CATEGORY_FILTER = "SKIPPED_CATEGORY_FILTER"  # --category flag excluded this tester
    SKIPPED_BUDGET = "SKIPPED_BUDGET"                  # --max-llm-* ceiling reached
    SKIPPED_UNCLASSIFIED = "SKIPPED_UNCLASSIFIED"      # Only UNKNOWN endpoints matched
    TARGET_RATE_LIMITED = "TARGET_RATE_LIMITED"        # Target returned 429s past retry budget


# Statuses that scoring treats as "did not run" (no risk attributed).
SKIPPED_STATUSES: frozenset[TestStatus] = frozenset({
    TestStatus.SKIPPED,
    TestStatus.SKIPPED_CAPABILITY,
    TestStatus.SKIPPED_TRANSPORT,
    TestStatus.SKIPPED_CATEGORY_FILTER,
    TestStatus.SKIPPED_BUDGET,
    TestStatus.SKIPPED_UNCLASSIFIED,
    TestStatus.TARGET_RATE_LIMITED,
})


class RiskCategory(str, Enum):
    ASI01 = "ASI01"
    ASI02 = "ASI02"
    ASI03 = "ASI03"
    ASI04 = "ASI04"
    ASI05 = "ASI05"
    ASI06 = "ASI06"
    ASI07 = "ASI07"
    ASI08 = "ASI08"
    ASI09 = "ASI09"
    ASI10 = "ASI10"
    # Extended test modules (EXT01-EXT09)
    EXT01 = "EXT01"  # Indirect Log Injection
    EXT02 = "EXT02"  # LTL Invariant Chain Validator
    EXT03 = "EXT03"  # Gossip Consensus Spoofer
    EXT04 = "EXT04"  # Active Inference Entropy Boundary
    EXT05 = "EXT05"  # Metamorphic Consistency Checker
    EXT06 = "EXT06"  # Z3 Constraint Satisfaction Prober
    EXT07 = "EXT07"  # Hierarchical Goal Drift Injector
    EXT08 = "EXT08"  # Sandbox Isolation Wrapper
    EXT09 = "EXT09"  # Neuro-Symbolic FOL Axiom Enforcer
    EXT10 = "EXT10"  # XPIA — Cross-Prompt Indirect Injection via External Data
    EXT11 = "EXT11"  # MCP Tool Poisoning Scanner
    EXT12 = "EXT12"  # Agent Alignment Checker (CoT Goal Drift)
    EXT13 = "EXT13"  # Behavioral Model Extraction via Query Oracle
    EXT14 = "EXT14"  # Data Poisoning via Training Endpoint
    EXT15 = "EXT15"  # Attribute Inference via SQL Response Analysis
    EXT16 = "EXT16"  # Semantic Cache Poisoning via Qdrant Embedding Collision
    EXT17 = "EXT17"  # Delivery Hijack via Email / Google Sheets Redirection

    @property
    def title(self) -> str:
        return CATEGORY_TITLES[self]

    @property
    def default_severity(self) -> Severity:
        return CATEGORY_SEVERITY[self]


CATEGORY_TITLES = {
    RiskCategory.ASI01: "Agent Goal Hijack",
    RiskCategory.ASI02: "Tool Misuse & Exploitation",
    RiskCategory.ASI03: "Identity & Privilege Abuse",
    RiskCategory.ASI04: "Agentic Supply Chain Vulnerabilities",
    RiskCategory.ASI05: "Unexpected Code Execution",
    RiskCategory.ASI06: "Memory & Context Poisoning",
    RiskCategory.ASI07: "Insecure Inter-Agent Communication",
    RiskCategory.ASI08: "Cascading Failures",
    RiskCategory.ASI09: "Human-Agent Trust Exploitation",
    RiskCategory.ASI10: "Rogue Agents",
    # Extended
    RiskCategory.EXT01: "Indirect Log Injection",
    RiskCategory.EXT02: "LTL Invariant Chain Validator",
    RiskCategory.EXT03: "Gossip Consensus Spoofer",
    RiskCategory.EXT04: "Active Inference Entropy Boundary",
    RiskCategory.EXT05: "Metamorphic Consistency Checker",
    RiskCategory.EXT06: "Z3 Constraint Satisfaction Prober",
    RiskCategory.EXT07: "Hierarchical Goal Drift Injector",
    RiskCategory.EXT08: "Sandbox Isolation Wrapper",
    RiskCategory.EXT09: "Neuro-Symbolic FOL Axiom Enforcer",
    RiskCategory.EXT10: "XPIA — Indirect Prompt Injection via External Data",
    RiskCategory.EXT11: "MCP Tool Poisoning Scanner",
    RiskCategory.EXT12: "Agent Alignment Checker (CoT Goal Drift)",
    RiskCategory.EXT13: "Behavioral Model Extraction via Query Oracle",
    RiskCategory.EXT14: "Data Poisoning via Training Endpoint",
    RiskCategory.EXT15: "Attribute Inference via SQL Response Analysis",
    RiskCategory.EXT16: "Semantic Cache Poisoning via Embedding Collision",
    RiskCategory.EXT17: "Delivery Hijack — Email & Sheets Redirection",
}

CATEGORY_SEVERITY = {
    RiskCategory.ASI01: Severity.CRITICAL,
    RiskCategory.ASI02: Severity.CRITICAL,
    RiskCategory.ASI03: Severity.CRITICAL,
    RiskCategory.ASI04: Severity.HIGH,
    RiskCategory.ASI05: Severity.CRITICAL,
    RiskCategory.ASI06: Severity.HIGH,
    RiskCategory.ASI07: Severity.HIGH,
    RiskCategory.ASI08: Severity.CRITICAL,
    RiskCategory.ASI09: Severity.HIGH,
    RiskCategory.ASI10: Severity.CRITICAL,
    # Extended
    RiskCategory.EXT01: Severity.CRITICAL,
    RiskCategory.EXT02: Severity.CRITICAL,
    RiskCategory.EXT03: Severity.CRITICAL,
    RiskCategory.EXT04: Severity.HIGH,
    RiskCategory.EXT05: Severity.HIGH,
    RiskCategory.EXT06: Severity.HIGH,
    RiskCategory.EXT07: Severity.HIGH,
    RiskCategory.EXT08: Severity.HIGH,
    RiskCategory.EXT09: Severity.MEDIUM,
    RiskCategory.EXT10: Severity.CRITICAL,
    RiskCategory.EXT11: Severity.CRITICAL,
    RiskCategory.EXT12: Severity.HIGH,
    RiskCategory.EXT13: Severity.HIGH,
    RiskCategory.EXT14: Severity.CRITICAL,
    RiskCategory.EXT15: Severity.HIGH,
    RiskCategory.EXT16: Severity.CRITICAL,  # Cache poisoning serves malicious SQL to all future users
    RiskCategory.EXT17: Severity.CRITICAL,  # Financial data exfiltration via email redirect
}

# CWE mappings per ASI category
CWE_MAPPING: dict[RiskCategory, list[str]] = {
    RiskCategory.ASI01: ["CWE-74", "CWE-20", "CWE-77"],
    RiskCategory.ASI02: ["CWE-89", "CWE-862", "CWE-400"],
    RiskCategory.ASI03: ["CWE-269", "CWE-284", "CWE-863"],
    RiskCategory.ASI04: ["CWE-345", "CWE-494", "CWE-829"],
    RiskCategory.ASI05: ["CWE-94", "CWE-918", "CWE-78"],
    RiskCategory.ASI06: ["CWE-345", "CWE-472", "CWE-915"],
    RiskCategory.ASI07: ["CWE-290", "CWE-294", "CWE-346"],
    RiskCategory.ASI08: ["CWE-400", "CWE-770", "CWE-834"],
    RiskCategory.ASI09: ["CWE-451", "CWE-356", "CWE-1021"],
    RiskCategory.ASI10: ["CWE-693", "CWE-841", "CWE-691"],
    # Extended
    RiskCategory.EXT01: ["CWE-116", "CWE-74", "CWE-20"],
    RiskCategory.EXT02: ["CWE-362", "CWE-613", "CWE-841"],
    RiskCategory.EXT03: ["CWE-290", "CWE-693", "CWE-284"],
    RiskCategory.EXT04: ["CWE-400", "CWE-693", "CWE-770"],
    RiskCategory.EXT05: ["CWE-116", "CWE-20", "CWE-435"],
    RiskCategory.EXT06: ["CWE-89", "CWE-682", "CWE-20"],
    RiskCategory.EXT07: ["CWE-840", "CWE-841", "CWE-693"],
    RiskCategory.EXT08: ["CWE-668", "CWE-345", "CWE-472"],
    RiskCategory.EXT09: ["CWE-682", "CWE-20", "CWE-284"],
    RiskCategory.EXT10: ["CWE-74", "CWE-20", "CWE-829"],   # Injection via external data
    RiskCategory.EXT11: ["CWE-345", "CWE-494", "CWE-74"],  # Untrusted tool definitions
    RiskCategory.EXT12: ["CWE-840", "CWE-841", "CWE-693"], # Goal/behavior deviation
    RiskCategory.EXT13: ["CWE-200", "CWE-203", "CWE-918"], # Info disclosure / model theft
    RiskCategory.EXT14: ["CWE-345", "CWE-915", "CWE-472"], # Data integrity / poisoning
    RiskCategory.EXT15: ["CWE-200", "CWE-359", "CWE-203"], # Privacy attribute leakage
    RiskCategory.EXT16: ["CWE-345", "CWE-441", "CWE-116"], # Unverified cache integrity / confused deputy
    RiskCategory.EXT17: ["CWE-601", "CWE-610", "CWE-200"], # Open redirect / unvalidated forward / data leak
}

# OWASP LLM Top 10 cross-references
OWASP_LLM_MAPPING: dict[RiskCategory, str] = {
    RiskCategory.ASI01: "LLM01",
    RiskCategory.ASI02: "LLM07",
    RiskCategory.ASI03: "LLM06",
    RiskCategory.ASI04: "LLM05",
    RiskCategory.ASI05: "LLM02",
    RiskCategory.ASI06: "LLM08",
    RiskCategory.ASI07: "LLM07",
    RiskCategory.ASI08: "LLM04",
    RiskCategory.ASI09: "LLM09",
    RiskCategory.ASI10: "LLM02",
    # Extended
    RiskCategory.EXT01: "LLM01",
    RiskCategory.EXT02: "LLM02",
    RiskCategory.EXT03: "LLM09",
    RiskCategory.EXT04: "LLM04",
    RiskCategory.EXT05: "LLM01",
    RiskCategory.EXT06: "LLM07",
    RiskCategory.EXT07: "LLM02",
    RiskCategory.EXT08: "LLM08",
    RiskCategory.EXT09: "LLM07",
    RiskCategory.EXT10: "LLM01",   # Prompt injection (indirect)
    RiskCategory.EXT11: "LLM05",   # Supply chain (tool definitions)
    RiskCategory.EXT12: "LLM06",   # Excessive agency / goal drift
    RiskCategory.EXT13: "LLM02",   # Sensitive info disclosure / model theft
    RiskCategory.EXT14: "LLM04",   # Data and model poisoning
    RiskCategory.EXT15: "LLM02",   # Sensitive information disclosure
    RiskCategory.EXT16: "LLM08",   # Vector and embedding weaknesses (cache store)
    RiskCategory.EXT17: "LLM06",   # Excessive agency — unvalidated output delivery
}
