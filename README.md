# OWASP ASI v3 — Agent-Agnostic Security Testing Platform

Point this scanner at any agentic-AI service (URL + OpenAPI spec + optional
bearer token) and it will:

1. **Discover** — fetch the OpenAPI/Swagger spec, classify endpoints by
   purpose (chat / tool-invoke / memory / file-IO / code-exec / health /
   auth), infer agent capabilities + risk tier.
2. **Plan** — pick which of 27 OWASP ASI + extension categories apply
   (optionally LLM-driven via Claude).
3. **Scan** — run the relevant testers via a transport-neutral adapter
   with rate-limit + 429 retry + session-lifecycle management.
4. **Triage** — optionally use Claude to disambiguate uncertain findings.
5. **Report** — JSON, SARIF (GitHub Code Scanning), JUnit, HTML.

No per-agent code changes. No hardcoded endpoint paths. No financial-domain
assumptions.

---

## Quickstart

```bash
pip install -r requirements.txt

# 1. Discover — produces an AgentProfile JSON
python cli.py discover \
  --url https://your-agent.example.com \
  --openapi-url https://your-agent.example.com/openapi.json \
  --auth-env YOUR_AGENT_TOKEN \
  --out profile.json

# 2. Plan — decide what to run (use --llm for Claude-driven planning)
python cli.py plan --profile profile.json --out plan.json

# 3. Scan
python cli.py scan-v3 --profile profile.json --plan plan.json

# Optional: enable Claude for planning + payload synthesis + triage
export ANTHROPIC_API_KEY=sk-ant-...
python cli.py scan-v3 --profile profile.json --plan plan.json \
  --llm --max-llm-spend-usd 2.00
```

Reports land in `results/<timestamp>_<agent>/` as `report.json`,
`report.sarif`, `report.junit.xml`, and `report.html`.

---

## Security model

The scanner ingests untrusted input from two sources (OpenAPI URLs you
supply and responses from the agent under test). Both are treated as
hostile by default:

| Defense | Where it lives | What it stops |
|---------|----------------|---------------|
| **SSRF guard** | [core/ssrf_guard.py](core/ssrf_guard.py) | Refuses RFC1918 / loopback / link-local / cloud-metadata IPs (v4 + v6). `--allow-internal` required for lab use. |
| **Token redaction** | [core/redaction.py](core/redaction.py) | Auto-registers the resolved auth token with a process-wide Redactor. Any echo of it from the agent is masked before it reaches logs, results JSON, or the LLM triager. |
| **Prompt-injection-resistant triage** | [llm/triage.py](llm/triage.py) | Agent responses are wrapped in `<untrusted_agent_response>` tags with explicit "data, not instructions" guardrails. Closing tags inside the response are defanged. Output is constrained tool-use JSON. |
| **Prompt-cache contract** | [llm/client.py](llm/client.py) | `assert_no_profile_leak()` blocks any system prompt that contains profile fields. Profile data MUST live in the user turn so the cached system prompt actually hits. |
| **Budget caps** | [llm/budget.py](llm/budget.py) | `--max-llm-calls` and `--max-llm-spend-usd` are hard ceilings. When hit, remaining categories are marked `SKIPPED_BUDGET` and the scan completes cleanly. |

### `--auth-env VAR` — never pass the token directly

The CLI takes the *name* of an environment variable, not the token value:

```bash
# DO NOT do this — the token lands in shell history + process listings
python cli.py discover --auth-token "sk-bearer-abc" ...

# Correct:
export MY_AGENT_TOKEN=sk-bearer-abc
python cli.py discover --auth-env MY_AGENT_TOKEN ...
```

This lets the Redactor register the token before any logging happens, keeps
it out of `ps`/shell history, and lets the adapter re-resolve a rotated
token mid-scan via `reset_session()`.

---

## CLI reference

```
python cli.py discover --url <agent>
                       [--openapi-url <spec>]      # else probe well-known
                       [--auth-env VAR]            # env-var NAME, not value
                       [--allow-internal]          # required for localhost
                       [--risk-tier low|medium|high|critical]
                       [--name NAME]
                       [--dry-run]
                       --out profile.json

python cli.py plan --profile profile.json
                   [--llm]                          # Claude-driven planner
                   [--max-payloads N]
                   --out plan.json

python cli.py scan-v3 --profile profile.json
                      [--plan plan.json]
                      [--dry-run]                  # adapter-INDEPENDENT walk
                      [--category ASI02 EXT10]     # others SKIPPED_CATEGORY_FILTER
                      [--llm]                      # planner + synth + triage
                      [--max-llm-calls N]
                      [--max-llm-spend-usd USD]
                      [--rate-limit-rpm N]
```

Legacy commands (`scan`, `health`, `register`, `report`) still work for the
original SQL-agent config-file path.

---

## Architecture

```
discover ─→ AgentProfile ─→ plan ─→ TestPlan ─→ scan-v3
              │                                    │
              ▼                                    ▼
         endpoints,                       TargetAdapter (REST/GraphQL/MCP)
         capabilities,                            │
         risk_tier                                ▼
                                          27 @register_tester classes
                                          (capability + transport gated)
                                                  │
                                                  ▼
                                     check_blocked → optional LLM triage
                                                  │
                                                  ▼
                                          report.{json,sarif,junit,html}
```

- **Discovery** ([discovery/](discovery/)) — OpenAPI parser + well-known
  prober + legacy manifest loader. Outputs `AgentProfile` v3.0.
- **Adapter** ([core/target_adapter.py](core/target_adapter.py)) —
  `RestAgentAdapter` is production. `GraphQLAgentAdapter` and
  `McpAgentAdapter` are stubs (planned for v2.1).
- **Registry** ([core/tester_registry.py](core/tester_registry.py)) —
  `@register_tester` carries `required_capabilities`,
  `applicable_transports`, `requires_clean_state`, `multi_turn`,
  `seed_payload_module`. The runner uses this metadata to gate every tester.
- **Runner** ([core/test_runner.py](core/test_runner.py)) —
  `run_with_profile()` enforces transport gating, capability gating,
  `--category` filter, multi-turn session lifecycle, `requires_clean_state`
  sequencing, and budget short-circuiting.
- **LLM layer** ([llm/](llm/)) — planner / payload synthesizer (with
  quality gate) / batched triager / budget governance. All optional; the
  scanner runs perfectly fine without `ANTHROPIC_API_KEY`.

---

## What's preserved from v1/v2

- The full 27-category test suite (ASI01–ASI10, EXT01–EXT17).
- The 3-layer `check_blocked` detection engine (structural + semantic +
  leak) — the crown jewel; untouched by the refactor.
- HTML / SARIF / JUnit / JSON reporters.
- OOB callback server for code-execution probing.
- All static payload libraries — now used as *seeds* for LLM synthesis.

---

## Test suite

```bash
pytest tests/                    # 107 v3 tests, all passing
pytest tests_asi/                # legacy tester unit tests
```

The integration suite uses [tests/fixtures/stub_agent/](tests/fixtures/stub_agent/)
— a FastAPI app with three deliberate vulnerabilities (prompt-injection
chat endpoint, UNION-SELECT SQL tool, path-traversal file reader) plus a
clean `/healthz` control. Every CI run scans this stub end-to-end, so the
pipeline never depends on an external service.

---

## CI / GitHub Actions

[pipeline.yml](pipeline.yml) — manual or scheduled. Parameterized inputs:
`agent_url`, `openapi_url`, `auth_token_secret` (name of a repo secret),
`categories`, `use_llm`, `max_llm_spend_usd`, `allow_internal`.

Pushes SARIF to GitHub Code Scanning, publishes JUnit results, uploads the
full report directory as an artifact, comments PRs with the risk score.

---

## Migration from v1/v2

See [MIGRATION.md](MIGRATION.md). Short version: legacy `AgentConfig` JSON
files still work via `register --config` and `scan --config`; for new
agents, use `discover → plan → scan-v3`.
