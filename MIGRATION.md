# Migration Guide

> Two migrations are documented in this file.  The current one is **v2 → v3**
> (agent-agnostic refactor, this section).  The earlier subprocess→pure-Python
> migration is preserved below for historical reference.

---

# v2 → v3: Agent-Agnostic Refactor

## What changed

v2 was hardcoded for one financial SQL agent: endpoint paths (`/api/ask`,
`/api/forecast`, etc.), the request shape (`{"question": "..."}`), 13
hardcoded `additional_endpoints`, and a manually-maintained `_MODULE_MAP`
test registry. v3 is generic: point it at any agent's OpenAPI spec and it
discovers everything automatically.

| Concept | v1/v2 | v3 |
|---------|-------|----|
| Target description | `AgentConfig` + `RemoteConfig` (hardcoded financial endpoints) | `AgentProfile` (built from OpenAPI / well-known probe / manifest) |
| Endpoint catalog | 13 hardcoded `additional_endpoints` strings | `EndpointSpec[]` with `EndpointPurpose` enum (CHAT/TOOL_INVOKE/MEMORY_*/FILE_IO/CODE_EXEC/HEALTH/AUTH/UNKNOWN) |
| Auth | `auth_headers` dict (token inline in JSON) | `AuthConfig` with `token_env_var` only — never inline; auto-registered with Redactor |
| Test registry | `_MODULE_MAP` in `test_runner.py` | `@register_tester` decorator with `required_capabilities`, `applicable_transports`, `requires_clean_state`, `multi_turn`, `seed_payload_module` metadata |
| Runner | `run_all(config)` | `run_with_profile(profile, plan, adapter, llm_context)` with full capability + transport gating, `SessionHandle` lifecycle, budget short-circuiting |
| Transport | Always HTTP, fixed POST shape | `TargetAdapter` ABC + `RestAgentAdapter` (rate-limit token-bucket, 429 retry, session reset). GraphQL/MCP stubs ready for v2.1 |
| LLM | Not used | Optional planner + payload synthesizer (with quality gate) + batched triager, all behind `--llm` |
| Reports | Same SARIF/JUnit/HTML/JSON | Unchanged — the reporting layer was preserved verbatim |

## CLI changes

```
# v2 (still works for legacy configs)
python cli.py register --config sample_configs/financial_agent.json
python cli.py scan     --config sample_configs/financial_agent.json

# v3
python cli.py discover --url <agent> --openapi-url <spec> --auth-env VAR --out profile.json
python cli.py plan     --profile profile.json [--llm] --out plan.json
python cli.py scan-v3  --profile profile.json --plan plan.json [--llm --max-llm-spend-usd 2.00]
```

## Migrating an existing v2 config

`models/agent_profile.py::migrate_remote_config()` translates a legacy
`AgentConfig` into a v3 `AgentProfile`. It maps the 13 hardcoded
`additional_endpoints` into `EndpointSpec` records with best-guess
purpose classification, infers capabilities from tool names, and emits a
stderr diff so you can review unclassified entries (marked `UNKNOWN`).

```python
from models.agent_config import AgentConfig
from models.agent_profile import migrate_remote_config
import json

raw = json.loads(open("sample_configs/financial_agent.json").read())
legacy = AgentConfig.model_validate(raw)
profile, diff_lines = migrate_remote_config(legacy)
print("\n".join(diff_lines))
open("migrated_profile.json", "w").write(profile.model_dump_json(indent=2))
```

A golden-file test ([tests/test_agent_profile.py](tests/test_agent_profile.py))
asserts the migrator output stays deterministic across releases.

## Breaking changes

- **`scan-v3`** is a new command; the legacy `scan --config` still works.
- **Auth tokens** must now be supplied via env var (`--auth-env VAR`), not
  inline JSON. Existing `auth_headers` in legacy configs are detected and a
  warning is emitted during migration.
- **CI pipeline** ([pipeline.yml](pipeline.yml)) now takes `agent_url` /
  `openapi_url` / `auth_token_secret` inputs instead of a hardcoded port
  8080 + financial-agent config path.

## What did NOT change

- The 27-category test suite (ASI01–ASI10, EXT01–EXT17).
- The 3-layer `check_blocked` detection engine (the crown jewel).
- HTML / SARIF / JUnit / JSON reporters.
- OOB callback server for code-execution probing.
- Static payload libraries — now reused as seeds for LLM synthesis.

---

# Original: Subprocess Era → Pure-Python Pipeline

> This section describes a separate, earlier migration (network-pipeline
> sibling project). Preserved here for historical reference; not relevant
> to v3 of the OWASP ASI Security Module.

## Overview

This document describes the breaking change from the subprocess-based pipeline
(Phases 1–5, using Go binaries and system tools) to the pure-Python redesign.

**This is a deliberate clean break.** Old engagement folders remain on disk for
archival but **cannot be resumed** under the new code.

---

## New Installation (pure Python, no Go toolchain)

```bash
# Base install — all scanners except DOM XSS + auth flows
pip install -e ".[network]"

# Optional: DOM XSS scanning + Playwright-backed auth flows
pip install -e ".[network,network-browser]"
playwright install chromium   # one-time ~600 MB download

# Optional: sqlmap deep-dive (confirmed SQLi extraction only)
pip install sqlmap

# Optional: API/web UI for click-to-run engagements
pip install -e ".[network,api]"
```

**No Go toolchain required. No `apt install nmap`. No PATH wrangling.**

---

## What Changed

### Tools Replaced

| Old (subprocess binary) | New (pure-Python scanner) |
|---|---|
| `subfinder` | `scanners/subdomains.py` — CT logs + HackerTarget + AlienVault + VirusTotal |
| `dnsx` | `scanners/dns_scan.py` — dnspython |
| `whois` binary | `scanners/whois_lookup.py` — RDAP API |
| `nmap` | `scanners/port_scan.py` — asyncio TCP connect-scan + banner-grab |
| `httpx` (PD) | `scanners/http_probe.py` — httpx + wappalyzer-ish tech detection |
| `nuclei` | `scanners/cve_check.py` — YAML check engine (bundled + custom) |
| `ffuf` / `feroxbuster` | `scanners/content_discovery.py` — concurrent httpx + wordlists |
| `getJS` + `linkfinder` | `scanners/js_endpoints.py` — BeautifulSoup + LinkFinder regex |
| `paramspider` + `arjun` | `scanners/parameter_mining.py` — Wayback CDX + live brute |
| `dalfox` | `scanners/xss_scan.py` — context-aware canaries |
| `sqlmap` binary | `scanners/sqli_scan.py` (detection) + `scanners/sqlmap_dispatch.py` (pip sqlmap deep-dive) |
| `jwt_tool` | `scanners/jwt_scan.py` — pyjwt + cryptography |
| `wapiti` / `nikto` / `zap-baseline.py` | `scanners/web_audit.py` — CORS + misconfig + injection breadth |

### Architecture That Stayed the Same

- All agent roles: orchestrator, recon, scanner, exploit, postexploit, analyst, defender, verifier
- `core/` infrastructure: budget, rate_limit, evidence_chain, RAG, supervisor, episodic, etc.
- FastAPI service + curated allowlist (`api/targets.json`) + click-to-run UI
- YAML playbooks, C2 profiles, OPSEC gate, OPPLAN/RoE schema
- Knowledge graph, findings.jsonl, Merkle audit chain

---

## Archiving Old Engagements

Old engagement folders (`engagements/<target>/<timestamp>/`) remain on disk.
The `tool_io/` sub-folders contain subprocess stdout/stderr files and Merkle leaves
that reference binary paths that no longer exist.

**To archive before upgrade:**
```bash
tar czf engagements-pre-redesign.tar.gz engagements/
```

After archiving, new runs land in fresh timestamped folders and coexist without contamination.

---

## One Documented Subprocess Exception

`sqlmap` remains as a **pip-installable** subprocess exception:

```
pip install sqlmap
```

When installed, `scanners/sqlmap_dispatch.py` spawns:
```
python -m sqlmap -u <url> --batch --level=1 --risk=1 ...
```

An explicit flag allowlist prevents dangerous options (`--os-shell`, `--file-write`, etc.).
When sqlmap is not installed, the `sqlmap_dispatch` @tool is automatically gated out by the
capability gate and detection-only coverage continues via `sqli_scan.py`.

---

## Adding Custom CVE Checks

Drop YAML files matching the schema in `skills/checks/README.md` into:
- `network_pipeline/skills/checks/cves/` (bundled, shipped with the package)
- `workspace/checks/` (per-engagement, not shipped)

---

## Known Gaps vs Subprocess Era

| Feature | Status |
|---|---|
| Full cipher-suite enumeration (sslyze) | Deferred to v1.1 — `pip install sslyze` optional extra |
| Blind SSRF (OOB callback) | Deferred to v1.1 — requires `--oob-port` listener |
| nuclei template compatibility | Not a goal — use CVE YAML format + nuclei→check converter (v1.1) |
| Stored XSS detection | Deferred — requires site-specific knowledge |
| DOM XSS without Playwright | Only reflected path; install playwright for full DOM coverage |

---

## Capability Gate Output

On iteration 1, the log now shows which Python libs are runnable instead of
missing-binary errors:

```
capability_gate dropped tools (missing libs): tls_audit(needs cryptography)
```

Compare to the old output that produced `findings=0` on Windows:
```
binary unavailable: subfinder (tool wrappers will skip)
binary unavailable: nuclei (tool wrappers will skip)
... 15 more binaries missing
```
