# Demo: scanning the Damn Vulnerable AI Agent (DVAA)

This walkthrough scans a real, intentionally-vulnerable LLM agent end-to-end
to demonstrate the v3 pipeline. Total time: ~5 minutes.

## What is DVAA?

[Damn Vulnerable AI Agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
("DVWA for AI agents") is an open-source project that ships six deliberately-
vulnerable LLM agents over OpenAI-compatible / MCP / A2A protocols. It runs
in Docker with a *simulated* LLM backend, so you don't need an API key.

We target **port 7003 (LegacyBot)** — all vulnerabilities enabled. Compare
to **port 7001 (SecureBot)** for a hardened baseline.

---

## Prerequisites

- Docker (with `docker compose`)
- Python 3.11+
- This repo, dependencies installed: `pip install -r requirements.txt`

Optional (for the LLM planner / synthesizer / triager):
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Step 1 — start DVAA

```bash
git clone https://github.com/opena2a-org/damn-vulnerable-ai-agent.git
cd damn-vulnerable-ai-agent
docker compose up -d
cd -
```

Confirm it's healthy:
```bash
curl http://127.0.0.1:7003/health
# {"status":"ok",...}
```

Dashboard: <http://localhost:9000>

---

## Step 2 — run the demo

### One-shot (recommended)

**Windows (PowerShell):**
```powershell
.\demo\run_demo.ps1
```

**Linux / macOS / WSL:**
```bash
bash demo/run_demo.sh
```

That script:
1. Waits for DVAA's `/health` to come up (60 s timeout).
2. Loads the pre-built profile [sample_configs/dvaa_agent.json](../sample_configs/dvaa_agent.json).
3. Runs `cli.py plan --profile ... --out plan.json`.
4. Runs `cli.py scan-v3 --profile ... --plan ...`.
5. Prints the path to the generated reports (JSON / SARIF / JUnit / HTML).

### Manual (each step visible)

```bash
# 1. Validate the pre-built profile
python cli.py register --config sample_configs/dvaa_agent.json   # optional sanity check

# 2. Build a plan (stub planner)
python cli.py plan --profile sample_configs/dvaa_agent.json --out demo_plan.json

# 3. Scan
python cli.py scan-v3 \
  --profile sample_configs/dvaa_agent.json \
  --plan demo_plan.json
```

### Demo with LLM planner + triage (Claude)

```bash
export ANTHROPIC_API_KEY=sk-ant-...

python cli.py plan --profile sample_configs/dvaa_agent.json --llm --out demo_plan.json

python cli.py scan-v3 \
  --profile sample_configs/dvaa_agent.json \
  --plan demo_plan.json \
  --llm --max-llm-spend-usd 2.00
```

The planner uses Claude to decide which categories apply. The triager
disambiguates findings whose detector confidence falls in the
`TRIAGE_AMBIGUITY_BAND` (default 0.4–0.7). Hard cost ceiling enforced.

---

## What you'll see

```
OK AgentProfile loaded
  Name:           dvaa_legacybot
  Base URL:       http://127.0.0.1:7003
  Endpoints:      3
  Capabilities:   tool_invoke, sql_query, web_browse
  Risk tier:      high (user)

OK TestPlan written to demo_plan.json
  Categories run: 25 / 27
  Skipped:        2

OWASP ASI v3 Security Scan
[============= per-category progress lines =============]

Reports written to results/20260523_120000_dvaa_legacybot/
  - report.json       full machine-readable
  - report.sarif      GitHub Code Scanning format
  - report.junit.xml  CI test runner format
  - report.html       dark-mode dashboard (open in browser)
```

Open `report.html` to walk through the findings during your demo.

---

## After the demo — tear down

```bash
cd /path/to/damn-vulnerable-ai-agent
docker compose down
```

---

## Other demo targets

- **Stub agent (zero setup):** `bash demo/run_demo.sh --target stub` —
  scans the in-repo FastAPI stub agent instead of DVAA. Slower to set up,
  but bulletproof if you don't have Docker.
- **Custom URL:** pass `--url https://your-agent --openapi-url ...` to
  `cli.py discover` and use the resulting profile.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `connection refused` on 7003 | DVAA hasn't started. `docker compose ps` to check. |
| Scan exits 1 with "CRITICAL vulnerabilities" | This is correct — DVAA is supposed to fail. The reports are still saved. |
| `LLMUnavailableError: ANTHROPIC_API_KEY not set` | Either `export ANTHROPIC_API_KEY=...` or drop the `--llm` flag. |
| SSRF guard blocks 127.0.0.1 | The pre-built profile uses the explicit IP. If you change to `localhost`, the demo script adds `--allow-internal` automatically. |
