<![CDATA[<div align="center">

# 🛡️ security-module

**Agent-Agnostic Safety & Red-Team Evaluation Harness for Agentic AI**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![OWASP ASI](https://img.shields.io/badge/OWASP-ASI%20Top%2010-EE3124?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)
[![Tests](https://img.shields.io/badge/tests-153%20passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![27 Threat Suites](https://img.shields.io/badge/threat%20suites-27-orange?style=for-the-badge&logo=target&logoColor=white)](tests_asi/)

---

Point it at **any** agentic-AI service (URL + OpenAPI spec + optional bearer token) and it
probes the target across **27 threat categories** (ASI01–ASI10 + EXT01–EXT17), captures
evidence, and produces structured **HTML / JSON / SARIF / JUnit** verdicts.

[Getting Started](#-quickstart) · [Architecture](#-architecture) · [Threat Classes](#-threat-classes-covered) · [CI/CD](#-cicd) · [Contributing](CONTRIBUTING.md)

</div>

> ⚠️ **Authorised testing only.** This is offensive security tooling — use responsibly.

---

## 📋 Table of Contents

- [Architecture](#-architecture)
- [End-to-End Pipeline](#-end-to-end-pipeline)
- [Component Architecture](#-component-architecture)
- [Threat Classes Covered](#-threat-classes-covered)
- [Probe Lifecycle](#-probe-lifecycle)
- [Quickstart](#-quickstart)
- [Configuration](#-configuration)
- [Project Structure](#-project-structure)
- [Agent Fingerprinting & Preflight](#-agent-fingerprinting--preflight)
- [Redaction](#-redaction)
- [CI/CD](#-cicd)
- [Migration Guide](#-migration-guide)
- [License](#-license)

---

## 🏗 Architecture

### High-Level System Overview

```mermaid
graph TB
    subgraph User["👤 Operator"]
        CLI["CLI / CI Runner"]
    end

    subgraph SecurityModule["🛡️ Security Module"]
        direction TB
        Discovery["🔍 Discovery<br/><i>OpenAPI Parser · Well-Known Prober · Manifest Loader</i>"]
        Preflight["✅ Preflight<br/><i>Reachability · Auth · Scope · Rate-Limit Budget</i>"]
        Fingerprinter["🔬 Agent Fingerprinter<br/><i>Family · Tools · Prompt Hints · Model Hints</i>"]
        Planner["📋 Planner<br/><i>LLM-Assisted or Stub · SKILL Pack Assembly</i>"]
        Runner["⚡ Test Runner<br/><i>Plan Executor · Verdict Aggregator</i>"]
        Reporter["📊 Reporter<br/><i>HTML · JSON · SARIF · JUnit</i>"]
    end

    subgraph ThreatSuites["🎯 27 Threat Suites"]
        ASI["ASI01–ASI10<br/><i>Goal Hijack · Tool Misuse · Privilege Abuse<br/>Supply Chain · Code Exec · Memory Poisoning<br/>Inter-Agent · Cascading · Trust · Rogue</i>"]
        EXT["EXT01–EXT17<br/><i>Log Injection · LTL Chain · Consensus Spoof<br/>Entropy Boundary · Metamorphic · Z3 Prober<br/>Goal Drift · Sandbox · FOL Axiom · XPIA<br/>MCP Poisoning · Alignment · Model Extraction<br/>Data Poisoning · Attribute Inference<br/>Cache Poisoning · Delivery Hijack</i>"]
    end

    subgraph Target["🤖 Target Agent"]
        Agent["Any Agentic AI Service<br/><i>LangChain · CrewAI · AutoGPT · Custom</i>"]
    end

    CLI --> Discovery
    Discovery --> Preflight
    Preflight --> Fingerprinter
    Fingerprinter --> Planner
    Planner --> Runner
    Runner --> ThreatSuites
    ThreatSuites --> Agent
    Agent -.->|"Responses"| Runner
    Runner --> Reporter
    Reporter -->|"Reports"| CLI

    style SecurityModule fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    style ThreatSuites fill:#16213e,stroke:#0f3460,stroke-width:2px,color:#eee
    style Target fill:#0f3460,stroke:#533483,stroke-width:2px,color:#eee
    style User fill:#1a1a2e,stroke:#e94560,stroke-width:1px,color:#eee
```

---

## 🔄 End-to-End Pipeline

```mermaid
flowchart LR
    A["🔑 Agent Profile<br/><i>URL + OpenAPI + Auth</i>"] --> B["✅ Preflight<br/><i>Reachability<br/>Auth Check<br/>Scope Guard<br/>Rate-Limit Budget</i>"]
    B --> C["🔬 Fingerprint<br/><i>Agent Family<br/>Tool Surface<br/>Model Hints<br/>Prompt Template</i>"]
    C --> D["📋 Plan<br/><i>SKILL Pack Assembly<br/>Attack Profile<br/>Stealth / Balanced / Loud</i>"]
    D --> E["⚡ Execute<br/><i>Run Probes<br/>Score Responses<br/>Collect Evidence<br/>Apply Redaction</i>"]
    E --> F["📊 Report<br/><i>HTML Dashboard<br/>JSON Verdicts<br/>SARIF Upload<br/>JUnit Results</i>"]

    style A fill:#e94560,stroke:#1a1a2e,stroke-width:2px,color:#fff
    style B fill:#533483,stroke:#1a1a2e,stroke-width:2px,color:#fff
    style C fill:#0f3460,stroke:#1a1a2e,stroke-width:2px,color:#fff
    style D fill:#16213e,stroke:#1a1a2e,stroke-width:2px,color:#fff
    style E fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#fff
    style F fill:#e94560,stroke:#1a1a2e,stroke-width:2px,color:#fff
```

### CLI Commands Mapping

```mermaid
flowchart TB
    subgraph CLI["CLI Entry Points"]
        discover["<b>cli.py discover</b><br/>--url · --openapi-url · --auth-env"]
        plan["<b>cli.py plan</b><br/>--profile · --llm"]
        scanv3["<b>cli.py scan-v3</b><br/>--profile · --plan · --fingerprint · --llm"]
        report["<b>cli.py report</b><br/>--results-dir"]
    end

    discover -->|"profile.json"| plan
    plan -->|"plan.json"| scanv3
    scanv3 -->|"results/"| report

    subgraph Outputs["📂 Outputs"]
        html["report.html"]
        json["verdicts.json"]
        sarif["report.sarif"]
        junit["report.junit.xml"]
        evidence["evidence/*.json"]
    end

    report --> Outputs

    style CLI fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    style Outputs fill:#16213e,stroke:#0f3460,stroke-width:2px,color:#eee
```

---

## 🧩 Component Architecture

```mermaid
graph TB
    subgraph Core["core/"]
        preflight["preflight.py<br/><i>Reachability + Scope + Rate-Limit</i>"]
        fingerprinter["agent_fingerprinter.py<br/><i>Black-box target inference</i>"]
        runner["test_runner.py<br/><i>Plan executor + verdict aggregator</i>"]
        adapter["target_adapter.py<br/><i>REST adapter · Token bucket · 429 retry</i>"]
        redaction["redaction.py<br/><i>API keys · JWTs · PII masking</i>"]
        base_tester["base_tester.py<br/><i>Abstract tester base class</i>"]
        registry["tester_registry.py<br/><i>@register_tester decorator</i>"]
        http["http_client.py<br/><i>Shared HTTP with retries</i>"]
        ssrf["ssrf_guard.py<br/><i>SSRF protection</i>"]
        stub["stub_planner.py<br/><i>Offline planner</i>"]
        callback["callback_server.py<br/><i>OOB callback for code-exec probing</i>"]
    end

    subgraph LLM["llm/"]
        planner_llm["planner.py<br/><i>LLM attack plan assembly</i>"]
        client["client.py<br/><i>Provider-agnostic LLM client</i>"]
        openai["openai_client.py<br/><i>OpenAI provider</i>"]
        synthesizer["payload_synthesizer.py<br/><i>LLM payload generation</i>"]
        triage["triage.py<br/><i>Batched verdict triaging</i>"]
        budget["budget.py<br/><i>Spend tracking + hard cap</i>"]
        context["context.py<br/><i>LLM session context</i>"]
    end

    subgraph Discovery["discovery/"]
        openapi["openapi_parser.py<br/><i>OpenAPI spec parsing</i>"]
        wellknown["well_known_prober.py<br/><i>Probe well-known paths</i>"]
        manifest["manifest_loader.py<br/><i>Agent manifest loading</i>"]
    end

    subgraph Models["models/"]
        profile["agent_profile.py<br/><i>Pydantic target schema</i>"]
        enums["enums.py<br/><i>Risk categories + severities</i>"]
        test_result["test_result.py<br/><i>Verdict + report models</i>"]
        test_plan["test_plan.py<br/><i>Plan schema</i>"]
    end

    subgraph Reporting["reporting/"]
        html_rep["html_reporter.py<br/><i>HTML dashboard</i>"]
        json_rep["json_reporter.py<br/><i>JSON verdicts</i>"]
        sarif_rep["sarif_reporter.py<br/><i>SARIF for GitHub</i>"]
        junit_rep["junit_reporter.py<br/><i>JUnit XML</i>"]
        summary["summary.py<br/><i>Posture score calculation</i>"]
    end

    subgraph Payloads["payloads/"]
        inj["injection_payloads.py"]
        enc["encoding_payloads.py"]
        poison["poisoning_payloads.py"]
        sql["sql_payloads.py"]
        xpia["xpia_payloads.py"]
    end

    runner --> adapter
    runner --> base_tester
    runner --> registry
    runner --> redaction
    adapter --> http
    adapter --> ssrf
    fingerprinter --> http
    planner_llm --> client
    client --> openai
    synthesizer --> client
    triage --> client
    client --> budget
    runner --> planner_llm
    runner --> stub
    base_tester --> Payloads

    style Core fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    style LLM fill:#16213e,stroke:#533483,stroke-width:2px,color:#eee
    style Discovery fill:#0f3460,stroke:#e94560,stroke-width:2px,color:#eee
    style Models fill:#1a1a2e,stroke:#0f3460,stroke-width:2px,color:#eee
    style Reporting fill:#16213e,stroke:#e94560,stroke-width:2px,color:#eee
    style Payloads fill:#0f3460,stroke:#533483,stroke-width:2px,color:#eee
```

---

## 🎯 Threat Classes Covered

The **27 attack suites** under `tests_asi/` are organized into two tiers:

### ASI Core (ASI01–ASI10) — OWASP Agentic Security Initiative

```mermaid
mindmap
  root((ASI Core<br/>Top 10))
    ASI01
      Goal Hijack
        Prompt override
        Objective manipulation
    ASI02
      Tool Misuse
        Argument poisoning
        Wrong-tool calls
    ASI03
      Privilege Abuse
        Escalation probes
        Scope violation
    ASI04
      Supply Chain
        Dependency confusion
        Plugin tampering
    ASI05
      Code Execution
        Sandbox escape
        OOB callbacks
    ASI06
      Memory Poisoning
        Long-term memory coercion
        Context manipulation
    ASI07
      Inter-Agent Comms
        Message injection
        Trust boundary crossing
    ASI08
      Cascading Failures
        Error amplification
        Chain reaction triggers
    ASI09
      Trust Exploitation
        Authority impersonation
        Delegation abuse
    ASI10
      Rogue Agents
        Behavioral deviation
        Goal misalignment
```

### Extended Suites (EXT01–EXT17)

| Suite | Code | What It Probes |
|:------|:-----|:---------------|
| **Log Injection** | `ext01` | Log forging, CRLF injection, log-based attacks |
| **LTL Chain** | `ext02` | Linear temporal logic chain violations |
| **Consensus Spoofer** | `ext03` | Multi-agent consensus manipulation |
| **Entropy Boundary** | `ext04` | Randomness boundary exploitation |
| **Metamorphic Consistency** | `ext05` | Semantic equivalence bypass |
| **Z3 Constraint Prober** | `ext06` | Formal constraint satisfaction attacks |
| **Goal Drift** | `ext07` | Gradual objective manipulation |
| **Sandbox Isolation** | `ext08` | Container/sandbox escape vectors |
| **FOL Axiom Enforcer** | `ext09` | First-order logic axiom violations |
| **XPIA Indirect Injection** | `ext10` | Cross-plugin indirect prompt injection |
| **MCP Tool Poisoning** | `ext11` | Model Context Protocol tool manipulation |
| **Alignment Checker** | `ext12` | Value alignment drift detection |
| **Model Extraction** | `ext13` | Model weights/behavior extraction |
| **Data Poisoning** | `ext14` | Training/inference data corruption |
| **Attribute Inference** | `ext15` | Private attribute leakage |
| **Cache Poisoning** | `ext16` | Cached-response replay attacks |
| **Delivery Hijack** | `ext17` | Gmail/Slack/webhook delivery hijacking |

---

## 🔬 Probe Lifecycle

Every probe in a suite produces one structured verdict:

```mermaid
sequenceDiagram
    participant R as Test Runner
    participant P as Probe Suite
    participant A as Target Adapter
    participant T as Target Agent
    participant Red as Redactor
    participant Rep as Reporter

    R->>P: Select probe from plan
    P->>P: Load payload (static + LLM-synthesized)
    P->>A: Send crafted request
    A->>T: HTTP request (rate-limited)
    T-->>A: Response
    A-->>P: Raw response
    P->>P: Score response<br/>(heuristics + LLM judge)
    P->>Red: Redact evidence (keys, JWTs, PII)
    Red-->>P: Sanitized evidence
    P-->>R: Verdict block
    R->>Rep: Aggregate verdicts
    Rep->>Rep: Compute posture score
    Rep-->>R: HTML + JSON + SARIF + JUnit
```

### Verdict Schema

```jsonc
{
  "probe_id": "ext1_prompt_injection.payload_05",
  "category": "prompt-injection",
  "severity_proposed": "high",
  "input": {
    "endpoint": "/chat",
    "headers": { "...": "..." },
    "body": { "message": "..." }
  },
  "response": {
    "status": 200,
    "body_snippet": "...",
    "latency_ms": 412
  },
  "verdict": "vulnerable",       // vulnerable | hardened | inconclusive
  "evidence": [
    {"type": "echo", "match": "secret-token-…", "redacted": true},
    {"type": "behaviour", "note": "Tool 'send_email' fired with attacker-controlled arg"}
  ],
  "suggestion": "Add system-prompt boundary; reject embedded instructions in tool arguments.",
  "correlation_id": "COR-..."
}
```

---

## 🚀 Quickstart

### Prerequisites

- **Python 3.11+**
- A target agentic-AI service with a reachable URL

### Installation

```bash
git clone https://github.com/krishddd/security-module.git
cd security-module

# Full setup: scanner + LLM providers + test tooling
pip install -e ".[llm,dev]"

# Core only (no LLM features):
pip install -r requirements.txt

cp .env.example .env   # set OPENAI_API_KEY / ANTHROPIC_API_KEY + target tokens
```

### Run Tests

```bash
# Unit suite (153 tests)
python -m pytest tests/ -q --ignore=tests/test_scan_v3_live.py
```

### Scan a Target

```bash
# 1. Discover the agent's shape
python cli.py discover --url http://localhost:3001 \
    --openapi-url http://localhost:3001/api-docs/json \
    --auth-env MY_TOKEN --out profile.json

# 2. Build an attack plan
python cli.py plan --profile profile.json --llm --out plan.json

# 3. Run the scan
python cli.py scan-v3 --profile profile.json --plan plan.json --llm --yes
```

### Demo Flows

```bash
# AnythingLLM (Docker, :3001)
pwsh demo/run_anythingllm_demo.ps1

# Odysseus (Docker, :7000)
pwsh demo/run_odysseus_demo.ps1
```

Reports are written to `results/<run_id>/report.html`. Per-run build artifacts go to `.work/` (gitignored).

---

## ⚙️ Configuration

Agent profiles are plain JSON. A minimal profile:

```json
{
  "name": "AnythingLLM demo",
  "target": "http://localhost:3001",
  "openapi": "http://localhost:3001/api-docs/json",
  "auth": { "type": "bearer", "token_env": "TARGET_TOKEN" },
  "scope": { "allow_hosts": ["localhost"], "deny_hosts": [] },
  "profile": "balanced",
  "tools_allowed": ["chat", "search", "send_email"],
  "rate_limit": { "rps": 2, "max_total": 500 }
}
```

The enriched profile shows what the fingerprinter populates after preflight.

### Attack Profiles

| Profile | Description |
|:--------|:------------|
| `stealth` | Low-volume, evasive probes — avoids triggering WAF/rate-limits |
| `balanced` | Default — covers breadth with moderate volume |
| `loud` | Full-blast — exhaustive coverage, may trigger defenses |

---

## 📁 Project Structure

```
├── cli.py                          # Command-line entry-point
├── pyproject.toml                  # Build config + dependencies
├── requirements.txt                # Pinned runtime deps
├── pipeline.yml                    # GitHub Actions CI/CD template
│
├── core/                           # Engine
│   ├── preflight.py                # Reachability + scope + rate-limit checks
│   ├── agent_fingerprinter.py      # Black-box target shape inference
│   ├── test_runner.py              # Plan executor + verdict aggregator
│   ├── target_adapter.py           # REST adapter with rate-limiting
│   ├── base_tester.py              # Abstract tester base class
│   ├── tester_registry.py          # @register_tester decorator
│   ├── redaction.py                # Evidence masking (API keys, JWTs, PII)
│   ├── http_client.py              # Shared HTTP client with retries
│   ├── ssrf_guard.py               # SSRF protection
│   ├── stub_planner.py             # Offline / dry-run planner
│   └── callback_server.py          # OOB callback for code-exec probing
│
├── llm/                            # LLM-assisted features (--llm flag)
│   ├── planner.py                  # Plan assembly from SKILL packs + fingerprint
│   ├── client.py                   # Provider-agnostic LLM client
│   ├── openai_client.py            # OpenAI provider
│   ├── payload_synthesizer.py      # LLM-based payload generation
│   ├── triage.py                   # Batched verdict triaging
│   ├── budget.py                   # Spend tracking + hard cap
│   └── context.py                  # LLM session context
│
├── discovery/                      # Target discovery
│   ├── openapi_parser.py           # OpenAPI spec parsing
│   ├── well_known_prober.py        # Probe well-known paths
│   └── manifest_loader.py          # Agent manifest loading
│
├── models/                         # Data models (Pydantic)
│   ├── agent_profile.py            # Target profile schema + v2→v3 migrator
│   ├── enums.py                    # Risk categories + severities
│   ├── test_result.py              # Verdict + report models
│   └── test_plan.py                # Plan schema
│
├── payloads/                       # Static payload libraries
│   ├── injection_payloads.py       # Prompt injection seeds
│   ├── encoding_payloads.py        # Encoding trick payloads
│   ├── poisoning_payloads.py       # Memory/data poisoning payloads
│   ├── sql_payloads.py             # SQL injection payloads
│   └── xpia_payloads.py            # Cross-plugin injection payloads
│
├── reporting/                      # Report generators
│   ├── html_reporter.py            # HTML posture dashboard
│   ├── json_reporter.py            # Machine-readable verdict log
│   ├── sarif_reporter.py           # SARIF for GitHub Code Scanning
│   ├── junit_reporter.py           # JUnit XML for CI integration
│   └── summary.py                  # Posture score calculation
│
├── tests_asi/                      # 27 attack/probe suites (production code)
│   ├── asi01–asi10                  # ASI core suites
│   └── ext01–ext17                 # Extended threat suites
│
├── tests/                          # Unit tests (pytest)
├── demo/                           # Demo scripts + docs
├── sample_configs/                 # Reference agent profiles
├── liveview/                       # Go-based live scan viewer
├── config/                         # Settings + agent registry
└── results/                        # Per-run reports (gitignored)
```

---

## 🔍 Agent Fingerprinting & Preflight

The pipeline does not assume what's on the other end. Two modules make that explicit:

```mermaid
flowchart LR
    subgraph Preflight["✅ Preflight Checks"]
        R["Reachability<br/>TCP + HTTP"]
        Auth["Auth Validation<br/>Token + Header"]
        Scope["Scope Guard<br/>Allow/Deny hosts"]
        Rate["Rate-Limit Budget<br/>RPS + Max Total"]
    end

    subgraph Fingerprint["🔬 Fingerprinting"]
        Family["Agent Family<br/><i>LangChain · CrewAI<br/>AutoGPT · Custom</i>"]
        Tools["Tool Surface<br/><i>Exposed capabilities</i>"]
        Prompt["Prompt Template<br/><i>System prompt hints</i>"]
        Model["Model Hints<br/><i>GPT-4 · Claude · etc.</i>"]
        RateP["Rate-Limit Posture<br/><i>Observed limits</i>"]
    end

    Target["🤖 Target Agent"] --> R
    R --> Auth
    Auth --> Scope
    Scope --> Rate
    Rate --> Family
    Family --> Tools
    Tools --> Prompt
    Prompt --> Model
    Model --> RateP
    RateP --> Plan["📋 Tailored<br/>Attack Plan"]

    style Preflight fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    style Fingerprint fill:#16213e,stroke:#533483,stroke-width:2px,color:#eee
```

- **`core/preflight.py`** — Checks reachability, auth correctness, scope boundaries (refuses out-of-scope hosts), rate-limit budget. Tests: `tests/test_preflight.py`
- **`core/agent_fingerprinter.py`** — Observes target responses and infers: agent family, tool surface, prompt-template hints, model hints, rate-limit posture. Tests: `tests/test_fingerprinter.py`

---

## 🔒 Redaction

`core/redaction.py` runs on every evidence object before persistence. It masks:

- 🔑 API keys & bearer tokens
- 🎫 JWTs & session tokens
- 👤 PII patterns (emails, phone numbers)
- 🏷️ Customer-specific identifiers

The resulting `results/<run_id>/` folder is safe to share with audit teams.

---

## 🔄 CI/CD

```mermaid
flowchart TB
    subgraph Triggers["Triggers"]
        push["Push to main"]
        pr["Pull Request"]
        dispatch["Manual Dispatch"]
        cron["Weekly Cron<br/><i>Mon 02:00 UTC</i>"]
    end

    subgraph Jobs["GitHub Actions Jobs"]
        lint["🔍 Lint + Unit Tests<br/><i>pytest · 153 tests · &lt;2 min</i>"]
        scan["🛡️ Live Security Scan<br/><i>discover → plan → scan-v3<br/>Up to 90 min</i>"]
        matrix["📊 Reference Matrix<br/><i>AnythingLLM + Odysseus<br/>Parallel execution</i>"]
    end

    subgraph Artifacts["Upload Artifacts"]
        sarif_up["SARIF → GitHub Code Scanning"]
        junit_up["JUnit → PR Check Results"]
        report_up["HTML Report → Artifacts"]
    end

    push --> lint
    pr --> lint
    dispatch --> lint
    cron --> lint
    lint --> scan
    lint --> matrix
    scan --> Artifacts
    matrix --> Artifacts

    style Triggers fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#eee
    style Jobs fill:#16213e,stroke:#533483,stroke-width:2px,color:#eee
    style Artifacts fill:#0f3460,stroke:#e94560,stroke-width:2px,color:#eee
```

The pipeline template lives in [`pipeline.yml`](pipeline.yml). To activate:

```bash
# Move to GitHub Actions location
mkdir -p .github/workflows
cp pipeline.yml .github/workflows/security.yml
```

---

## 📖 Migration Guide

See [MIGRATION.md](MIGRATION.md) for the full **v2 → v3** agent-agnostic refactor guide.

Key changes:
- **Agent-agnostic**: No more hardcoded endpoints — everything discovered via OpenAPI
- **`@register_tester` decorator**: Replaces the manual `_MODULE_MAP`
- **LLM-assisted planning**: Optional `--llm` flag for smarter attack plans
- **Auth via env vars**: Tokens never stored inline in config

---

## 📊 Status

Personal portfolio project. Agent-agnostic — designed to be aimed at any production or staging agentic-AI service you own.

## 📝 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with ❤️ for the agentic AI security community**

</div>
]]>
