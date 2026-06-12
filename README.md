# security-module

> Agent-agnostic safety and red-team evaluation harness. Point it at any
> agentic-AI service (URL + OpenAPI spec + optional bearer token) and it
> probes the target across 17+ extended ASI threat classes, captures
> evidence, and produces structured HTML / JSON verdicts.

`security-module` is a Python pipeline that treats every agentic-AI service
as a black-box target. It auto-discovers the target's shape (agent
fingerprinting + preflight), generates an attack plan from a SKILL library,
runs the plan, captures evidence for every probe, and renders a final report
the user can ship to a customer or audit team.

> ⚠️ **Authorised testing only.** This is offensive security tooling.

---

## End-to-end pipeline

```
Agent profile JSON (target URL + OpenAPI + auth)
        │
        ▼
core/preflight.py              ← reachability, auth, scope, rate-limit budget
        │
        ▼
core/agent_fingerprinter.py    ← detects agent family, tool surface,
                                 prompt-template hints, model hints
        │
        ▼
llm/planner.py                 ← assembles an attack plan from SKILL packs
                                 + the fingerprint signal; honours profile
                                 (stealth / balanced / loud)
        │
        ▼
core/stub_planner.py           ← offline / dry-run planner used in tests
        │
        ▼
core/test_runner.py            ← executes plan step-by-step:
        │  ├─ pick probe
        │  ├─ apply redaction (core/redaction.py) on stored evidence
        │  ├─ send request via target adapter
        │  ├─ score response (heuristics + judge prompts)
        │  └─ append to evidence log
        ▼
tests_asi/  ← 17 extended ASI suites mounted into the runner:
   ext1_prompt_injection
   ext2_jailbreak_persona
   ext3_tool_abuse
   ext4_data_exfil
   ext5_schema_confusion
   ext6_function_spoof
   ext7_indirect_prompt_injection
   …
   ext16_cache_poisoning
   ext17_delivery_hijack
        │
        ▼
reporting/html_reporter.py     ← renders HTML dashboard
reporting/json_reporter.py     ← machine-readable verdict log
        │
        ▼
results/<run_id>/
   ├─ report.html
   ├─ verdicts.json
   ├─ evidence/<probe_id>.json
   └─ plan.json
```

---

## What the runner does on every probe

Each probe in a suite produces one verdict block:

```jsonc
{
  "probe_id": "ext1_prompt_injection.payload_05",
  "category": "prompt-injection",
  "severity_proposed": "high",
  "input": {                  // request sent to target
    "endpoint": "/chat",
    "headers": { "...": "..." },
    "body": { "message": "..." }
  },
  "response": {               // captured response, with redaction applied
    "status": 200,
    "body_snippet": "...",
    "latency_ms": 412
  },
  "verdict": "vulnerable",    // vulnerable | hardened | inconclusive
  "evidence": [
    {"type": "echo", "match": "secret-token-…", "redacted": true},
    {"type": "behaviour", "note": "Tool 'send_email' fired with attacker-controlled arg"}
  ],
  "suggestion": "Add system-prompt boundary; reject embedded instructions in tool arguments.",
  "correlation_id": "COR-..."
}
```

The HTML reporter groups verdicts by category, computes a per-category and
overall posture score, and embeds the redacted evidence inline so a reviewer
can audit without re-running the probe.

---

## Threat classes covered

The 17 ASI extended suites under `tests_asi/` cover, at minimum:

| Suite                         | What it probes                                                  |
|-------------------------------|-----------------------------------------------------------------|
| Prompt Injection              | Direct + indirect injection, system-prompt extraction           |
| Jailbreak & Persona Hijack    | Role-play takeover, multi-turn persona drift                    |
| Tool Abuse                    | Wrong-tool calls, argument poisoning, recursion / explosion     |
| Data Exfiltration             | Long-context leak, embedding-via-URL, tool-output exfil         |
| Schema Confusion              | Malformed JSON, mixed encodings, type confusion                 |
| Function Spoofing             | Fake tool responses to mislead the agent                        |
| Indirect Prompt Injection     | RAG-poisoning, search-result injection, document injection      |
| Cross-Tool Influence          | One tool's output coercing the next tool's input                |
| Memory Poisoning              | Long-running memory tier coercion                               |
| Output Filter Bypass          | Encoding tricks, homoglyph, role smuggling                      |
| Cost / Latency DoS            | Tool-loop blowup, very-long-context attacks                     |
| Cache Poisoning               | Cached-response replay against new users                        |
| Delivery Hijack               | Hijacking Gmail / Slack / webhook deliveries                    |
| …                             | + 4 more bespoke ASI categories                                 |

---

## Agent fingerprinting & preflight

The pipeline does not assume what's on the other end. Two new modules
(landed in commit `a5a38a0`, refined in `1f8b459`) make that explicit:

- **`core/preflight.py`** — checks reachability, auth correctness, scope
  boundaries (refuses to test out-of-scope hosts), rate-limit budget, and
  prints a clear diagnostic if anything fails. Tests cover 257 lines of
  behaviour at `tests/test_preflight.py`.

- **`core/agent_fingerprinter.py`** — observes the target's responses to a
  handful of safe queries and infers: agent family (LangChain / LangGraph /
  CrewAI / AutoGPT-style / custom), exposed tool surface, prompt-template
  hints, model hints, and rate-limit posture. Tests cover 325 lines at
  `tests/test_fingerprinter.py`. The fingerprint feeds the planner so the
  attack plan is tailored to the target.

The demo flow (`demo/ODYSSEUS_DEMO.md` + `demo/run_odysseus_demo.ps1` +
`sample_configs/odysseus_agent.json`) walks through fingerprinting and
running the suite end-to-end against a sample agent.

---

## Redaction

`core/redaction.py` runs on every evidence object before persistence. It
masks API keys, JWTs, bearer tokens, PII patterns, and customer-specific
identifiers so the resulting `results/<run_id>/` folder is safe to share.

---

## Quickstart

```bash
git clone https://github.com/krishddd/security-module.git
cd security-module

# Full setup: scanner + LLM providers (--llm) + test tooling
pip install -e ".[llm,dev]"
#   Core only (runs a scan without --llm):   pip install -r requirements.txt
#   Test fixture (FastAPI stub agent):        pip install -e ".[stub]"

cp .env.example .env  # set OPENAI_API_KEY and target tokens

# Run the unit suite (153 tests)
python -m pytest tests/ -q --ignore=tests/test_scan_v3_live.py

# Demo flow against a live agent (discover → preflight → fingerprint → scan-v3)
pwsh demo/run_anythingllm_demo.ps1   # AnythingLLM (Docker, :3001)
pwsh demo/run_odysseus_demo.ps1      # Odysseus    (Docker, :7000)
```

Reports are written to `results/<run_id>/report.html`; per-run build
artifacts (profile, plan, OpenAPI spec) go to `.work/` (both gitignored).

---

## Project structure

```
cli.py                        Command-line entry-point
core/
├── preflight.py              Reachability + scope + rate-limit checks
├── agent_fingerprinter.py    Black-box target shape inference
├── stub_planner.py           Offline / dry-run planner
├── test_runner.py            Plan executor + verdict aggregator
└── redaction.py              Evidence masking
llm/
└── planner.py                Plan assembly from SKILL packs + fingerprint
models/
└── agent_profile.py          Pydantic schema for target profiles
tests_asi/                    Scanner tester modules (ASI01-10 + EXT suites).
                              NOTE: production code, not unit tests — these are
                              the attack/probe suites the runner executes.
reporting/
└── html_reporter.py          Posture HTML report
demo/
├── ODYSSEUS_DEMO.md
├── run_odysseus_demo.ps1
└── run_anythingllm_demo.ps1
sample_configs/
└── odysseus_agent.json       Committed agent profiles (read-only input)
tests/                        Unit tests (fingerprinter, preflight, profiles)
results/                      Per-run reports          (gitignored)
.work/                        Per-run build artifacts  (gitignored)
```

---

## Configuration

Profiles are plain JSON. A minimal profile:

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

The enriched profile (`demo_anythingllm_profile.enriched.json`) shows what
the fingerprinter populates after preflight.

---

## CI

GitHub Actions runs syntax checks and pytest. Demo PowerShell scripts are
linted via PSScriptAnalyzer.

---

## Status

Personal portfolio project. Agent-agnostic — designed to be aimed at any
production or staging agentic-AI service you own.

## License

MIT
