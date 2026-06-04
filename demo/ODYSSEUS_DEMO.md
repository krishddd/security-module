# Odysseus Real-World Demo (Second Target)

**Target:** [Odysseus](https://github.com/pewdiepie-archdaemon/odysseus) —
self-hosted autonomous AI workspace, 39k+ GitHub stars. Multi-service
docker compose. Built on opencode + MCP. **Real shell + file +
autonomous-agent surface.**

**The contrast with AnythingLLM (your first demo):**

| | AnythingLLM | Odysseus |
|---|---|---|
| Shape | Chat + RAG app | **Autonomous agent** |
| Tools | Workspaces, documents | **Shell, files, web, MCP tools, skills** |
| Risk surface | Medium | **Critical** (shell + file + MCP) |
| Expected findings | Auth + privacy | **Code-exec, sandbox, SSRF, MCP poisoning** |

This is your "different agent shape, same scanner" demo point.

---

## Total time
- **First run:** ~10–15 min (image pulls + 2-min UI setup + scan)
- **Subsequent runs:** ~3 min

---

## One-shot command

```powershell
cd C:\Users\hp\Downloads\Agent_security_testing\Security_module
.\demo\run_odysseus_demo.ps1
```

What the script does:
1. `git clone --depth=1` Odysseus into `..\..\odysseus` (if not already there)
2. Copies `.env.example` → `.env` and **injects your `OPENAI_API_KEY`** automatically (read from the scanner's `.env`)
3. `docker compose up -d --build` — brings up Odysseus + ChromaDB + SearXNG + ntfy
4. Waits up to 5 min for `http://localhost:7000` to respond
5. Greps the container logs for the temp admin password and prints it
6. **Pauses** while you log in, change the password, and generate an API token
7. Tries `http://localhost:7000/openapi.json` auto-discover; falls back to a pre-built profile if not served
8. Runs `cli.py plan` + `cli.py scan-v3`
9. Opens `results\<ts>_odysseus_local\report.html`

---

## The manual setup (~2 min, one time only)

When the script pauses and opens `http://localhost:7000`:

1. **Log in** as `admin` with the **temp password** (printed in your PowerShell window from container logs)
2. **Change the password** when prompted (any strong password)
3. Navigate to **Settings → API Tokens** (or **Admin → Tokens** — exact location depends on Odysseus version)
4. Click **"Create new token"** → copy the long token value
5. Switch back to PowerShell → paste the token → Enter

> If you can't find the temp password in the printed logs, run this manually:
> ```powershell
> cd C:\Users\hp\Downloads\odysseus
> docker compose logs odysseus | Select-String -Pattern "password"
> ```

---

## What you'll see during the demo

Expected results vs AnythingLLM:

| Category | AnythingLLM (yesterday) | Odysseus (expected) |
|---|---|---|
| **ASI05 Code Execution** | 2 VULN (low impact) | **MANY CRITICAL** — Odysseus has explicit shell endpoint |
| **EXT08 Sandbox Isolation** | 1 VULN | **MANY CRITICAL** — file system access is a core feature |
| **ASI03 Privilege Abuse** | 8 VULN | **HIGH** — admin endpoints exist |
| **EXT11 MCP Tool Poisoning** | 2 VULN | **CRITICAL** — Odysseus is MCP-native |
| **EXT17 Delivery Hijack** | 3 VULN | Lower (no email tooling shown) |
| **EXT15 Attribute Inference** | 3 CRITICAL | Similar |
| **Overall risk score** | 1.2 / 10 (LOW) | **Expected 5+ / 10** |

This contrast is the point. **Same scanner. Two different agent shapes. The threat profile mirrors what the agent actually exposes.**

---

## Demo narration (90 seconds)

> *"This is Odysseus — same scanner, completely different agent. 39 thousand GitHub stars. While AnythingLLM is a chat/RAG app, Odysseus is an autonomous agent — it runs shell commands, reads files, uses MCP tools.*
>
> *Watch what happens when I point the same scanner at it.*
>
> *[Script runs]*
>
> *Notice the risk score is higher than AnythingLLM. That's expected — Odysseus exposes shell-exec and file-IO as features. The scanner mapped those to ASI05 (Unexpected Code Execution) and EXT08 (Sandbox Isolation) and found real CRITICAL issues there.*
>
> *Look at this finding [click into an ASI05 VULN]: shell command executed. Here's the payload, here's the response, here's the remediation.*
>
> *Same scanner, different threat profile. That's the value — it understands what the agent CAN do and tests accordingly."*

---

## Expected categories breakdown

The LLM planner will probably skip (or run minimally):
- ASI07 (Inter-Agent Communication) — Odysseus is single-process
- ASI10 (Rogue Agents) — same
- EXT03 (Gossip Consensus Spoofer) — not a multi-agent system

The categories that will fire HARD against Odysseus:
- ASI01 Goal Hijack (autonomous agent = high-value target for jailbreaks)
- ASI02 Tool Misuse (multiple tool surfaces)
- ASI04 Supply Chain (skills + MCP = adjustable code path)
- **ASI05 Code Execution** (shell endpoint is a feature)
- **EXT08 Sandbox Isolation** (file ops = file system reach)
- **EXT11 MCP Tool Poisoning** (MCP-native!)
- EXT12 Alignment Checker (autonomous agent drift)
- ASI03 Privilege Abuse (admin endpoints exist)

---

## Cleanup

```powershell
cd C:\Users\hp\Downloads\odysseus
docker compose down -v
```

The `-v` removes the volumes (chroma data, your account, etc.). Drop it if you want to keep state for the next run.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker compose up` errors on Image build | Slow internet — let it retry; `--build` is one-time |
| `Odysseus did not respond within 5 minutes` | Check `docker compose logs odysseus`. Database init can be slow on first run. |
| Can't find temp password in logs | `docker compose logs odysseus 2>&1 \| Select-String password` — or check Docker Desktop's Logs view |
| API token rejected | Make sure you copied the token, not the token NAME. Some UIs show the token value only once. |
| /openapi.json returns 404 or HTML | Auto-discover fails gracefully → script falls back to pre-built profile automatically. No action needed. |
| Scan shows mostly PASSED | Some Odysseus versions ship with strict guardrails. Try with `-UseLlm` so the planner picks targeted attacks. |

---

## Two-agent demo flow (recommended order)

For tomorrow, run them in this order:

1. **AnythingLLM first** (~7 min) — you've already done this. Score: 1.2/10 LOW. The "even well-defended agents have gaps" story.
2. **Odysseus second** (~5 min for scan + already-set-up agent) — expected higher score. The "the scanner adapts to the agent's actual capabilities" story.

Total demo time: ~15 min including setup time + walk-through of both reports.

---

## Sticky-note quick reference

```
SECOND DEMO COMMAND (run on stage):
.\demo\run_odysseus_demo.ps1 -SkipDockerBootstrap -Token "your-odysseus-token-here"

PREP TONIGHT:
1. cd Security_module
2. .\demo\run_odysseus_demo.ps1                  (first time: clones repo, brings up stack)
3. Do the manual setup (login + token gen)
4. Save token in a text file for tomorrow
5. docker compose down -v  (or leave running)

ODYSSEUS URL:  http://localhost:7000
TOKEN FORMAT:  long random alphanumeric, NOT starting with "sk-"
```
