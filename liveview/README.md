# liveview — live terminal-to-browser bridge

A tiny Go sidecar that runs your **existing** scanner demo commands and streams
the live terminal output to a browser. It does **not** change the scanner — it
just spawns `demo\run_anythingllm_demo.ps1` / `demo\run_odysseus_demo.ps1`
exactly as you run them, captures stdout/stderr, and renders it live with
xterm.js (ANSI colors preserved).

Single binary, stdlib only — `go build` works fully offline.

## 1. Install Go (one time, ~2 min)

Download the Windows installer from <https://go.dev/dl/> (e.g. `go1.23.x.windows-amd64.msi`),
run it, then **open a new PowerShell** and confirm:

```powershell
go version
```

## 2. Run it (from the Security_module folder)

```powershell
cd C:\Users\hp\Downloads\Agent_security_testing\Security_module

# optional: preload tokens so you don't paste them in the browser
$env:ANYTHINGLLM_TOKEN = "4NJ570K-T3N48A3-J8B8FE0-WXBKJ6K"
$env:ODYSSEUS_TOKEN    = "ody_CoYk9ja7LDNmNCLTfEkl_3Nvz7TimsP3caJOoeexmi4"

# dev mode (no build step):
go run ./liveview

# OR build a single .exe and run that:
go build -o liveview.exe ./liveview
.\liveview.exe
```

Then open **http://127.0.0.1:8080**.

> Run it from the `Security_module` folder so it finds `demo\`. To run from
> elsewhere, pass `-root`:  `.\liveview.exe -root "C:\Users\hp\Downloads\Agent_security_testing\Security_module"`
> Change the port with `-port 9000`.

## 3. Use it (all clicks)

1. Pick **AnythingLLM** or **Odysseus** (green dot = reachable, red = down).
2. (optional) paste a token / tick **Use LLM**.
3. Click **Run scan** → watch the live terminal stream in the browser.
   - **Stop** kills the scan (whole process tree).
   - **Clear** wipes the screen.
4. When the scan finishes, the demo script opens the HTML report as usual.

## What maps to what

| Browser action | Command it runs |
|---|---|
| Run AnythingLLM | `powershell demo\run_anythingllm_demo.ps1 -SkipDockerBootstrap -ApiKey <token>` |
| Run AnythingLLM + LLM | `... -UseLlm -MaxLlmSpendUsd 0.50` |
| Run Odysseus | `powershell demo\run_odysseus_demo.ps1 -SkipDockerBootstrap -Token <token>` |
| Run Odysseus + LLM | `... -UseLlm -MaxLlmSpendUsd 0.50` |

Token resolution: browser field → `*_TOKEN` env var → baked demo default.

## Endpoints (for the UI team to build their own frontend)

| Method | Path | Purpose |
|---|---|---|
| GET  | `/` | the built-in viewer page |
| GET  | `/agents` | `[{Key,Label,Target,Reachable}]` for the health dots |
| POST | `/run?agent=anythingllm&llm=true&token=...` | start a scan |
| POST | `/stop` | kill the running scan |
| GET  | `/events` | **SSE** stream: `{type:"line",text}` and `{type:"status",running,agent}` |

The viewer page in `main.go` is the reference implementation — the UI team
can point their own page at `/events` + `/run` + `/stop`.
