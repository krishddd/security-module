# Demo Quickstart — exact commands to run

If your demo is happening soon, follow this in order. No detours.

---

## 0. One-time setup (5 min)

### Install dependencies
The recommended install pulls the scanner plus LLM providers and test tooling
from `pyproject.toml`:

```bash
python -m pip install -e ".[llm,dev]"
```

Core only (no `--llm`): `python -m pip install -r requirements.txt`.

> If `pip install` fails with `TypeError: sequence item 0: expected str instance, NoneType found` (a known Windows pip bug), upgrade pip first:
> ```powershell
> python -m ensurepip --upgrade
> python -m pip install --upgrade pip
> ```

### Verify the install
```powershell
cd C:\Users\hp\Downloads\Agent_security_testing\Security_module
python -c "from dotenv import load_dotenv; import anthropic, fastapi; print('OK')"
```
If you see `OK`, you're ready.

### Check your `.env`
Open `Security_module\.env`. It should already have:
```
ANTHROPIC_API_KEY=****************************    # leave masked for now
OPENAI_API_KEY=sk-proj-...                         # already filled in
```
The framework's LLM path uses Anthropic only — `OPENAI_API_KEY` is parked
for future use. **Without `ANTHROPIC_API_KEY`, the `--llm` flag is silently
skipped** (the scan still runs, just without LLM planning/triage).

---

## 1. Start the demo target (DVAA)

```powershell
cd <somewhere outside this repo>
git clone https://github.com/opena2a-org/damn-vulnerable-ai-agent.git
cd damn-vulnerable-ai-agent
docker compose up -d
```

Wait ~15 seconds, then confirm:
```powershell
curl http://127.0.0.1:7003/health
# {"status":"ok",...}
```
Dashboard: <http://localhost:9000>

---

## 2. Run the demo (one command)

Back in `Security_module/`:

```powershell
.\demo\run_demo.ps1
```

That's it. The script:
1. Waits for DVAA on `:7003` (60 s).
2. Loads the pre-built [sample_configs/dvaa_agent.json](../sample_configs/dvaa_agent.json).
3. Builds a TestPlan (`cli.py plan`).
4. Runs the full v3 scan (`cli.py scan-v3`).
5. Prints the path to `results/<timestamp>_dvaa_legacybot/`.

**Expected exit code:** `0` (clean) or `1` (CRITICAL vulnerabilities found).
A `1` is the *correct* outcome — DVAA is supposed to fail. Reports are
saved either way.

### Open the HTML report
```powershell
# The script prints the path; or:
Start-Process (Get-ChildItem .\results -Directory |
               Sort-Object LastWriteTime -Descending |
               Select-Object -First 1).FullName\report.html
```

---

## 3. (Optional) Re-run with the LLM planner + triager

Once you have your `ANTHROPIC_API_KEY`, edit `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...your-real-key...
```

Then:
```powershell
.\demo\run_demo.ps1 -UseLlm -MaxLlmSpendUsd 2.00
```

What changes:
- Claude picks which of 27 categories actually apply (instead of the stub
  planner running all of them).
- Findings whose detector confidence is in the 0.4–0.7 band get a
  second-opinion triage pass from Claude.
- The reports include a `triage` evidence block on the disambiguated
  findings.
- Spend is hard-capped at the value you pass (default `2.00` USD).

---

## 4. Demo narration cheat sheet

| Slide / moment | What to show / say |
|---|---|
| **The problem** | "v2 was hardcoded to one specific SQL agent — 13 endpoint paths, one auth shape, manual test registry." Show [sample_configs/financial_agent.json](../sample_configs/financial_agent.json) — point at the 13 `additional_endpoints`. |
| **The goal** | "Register *any* agent with just a URL + OpenAPI spec, no per-agent code." |
| **Discover** | Open [sample_configs/dvaa_agent.json](../sample_configs/dvaa_agent.json) — point out it's the same shape as the financial one but only 3 endpoints + an OpenAI-compatible chat schema. |
| **Run** | Execute `.\demo\run_demo.ps1`. Narrate the per-category lines as they stream. |
| **Findings** | Open `report.html`. Click into a FAILED finding — show the request payload, the response, the CWE / OWASP IDs, the remediation. |
| **The LLM angle** | "The same scan with `--llm` lets Claude pick categories per agent and triage ambiguous results." Re-run with `-UseLlm`. |
| **Safety** | Mention SSRF guard ([core/ssrf_guard.py](../core/ssrf_guard.py)), token redaction ([core/redaction.py](../core/redaction.py)), `--auth-env VAR` (never paste tokens). |
| **CI** | Open [pipeline.yml](../pipeline.yml) — parameterized inputs, SARIF push to GitHub Code Scanning. |

---

## 5. If something breaks during the demo

| Symptom | Quick fix |
|---|---|
| `connection refused on 7003` | `docker compose ps` in the DVAA dir; restart with `docker compose up -d`. |
| `LLMUnavailableError: ANTHROPIC_API_KEY not set` | Either drop the `-UseLlm` flag or paste a real key into `.env`. |
| Scan hangs on a slow category | `Ctrl+C` — partial results are still written to `results/`. |
| `python-dotenv` not installed | The `.env` won't auto-load, but the scan still works if the env vars are set in the shell. `python -m pip install python-dotenv` to fix. |
| Reports dir not created | Check that `Security_module\results\` exists and is writable. The first run creates it. |
| `SSRFBlockedError` mentioning 127.0.0.1 | Only fires in `discover` — the demo profile is pre-built so this shouldn't happen. If you're using `cli.py discover` against localhost, add `--allow-internal`. |

---

## 6. Cleanup after the demo

```powershell
# Stop DVAA
cd <wherever damn-vulnerable-ai-agent is>
docker compose down

# Optional: clear demo results + per-run build artifacts
Remove-Item -Recurse .\Security_module\results\* -Force
Remove-Item -Recurse .\Security_module\.work\* -Force
```

---

## Backup plan: scan the in-repo stub instead

If DVAA / Docker / internet is down during the demo:
```powershell
.\demo\run_demo.ps1 -Target stub
```
That uses the FastAPI stub agent shipped in this repo — zero external
dependencies, guaranteed to produce findings on `/chat`, `/sql_tool`,
`/file_read`. Same script, same flow.
