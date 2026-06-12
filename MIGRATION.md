# Migration Guide

> Documents the **v2 → v3** agent-agnostic refactor of the OWASP ASI Security
> Module.

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
