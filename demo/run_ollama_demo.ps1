<#
    Real-world demo runner -- scans a live Ollama instance (production LLM runtime).

    Why Ollama:
      - 300k+ public deployments (CVE-2026-7482 "Bleeding Llama")
      - No authentication by default
      - ~15 API endpoints across chat / models / embeddings / OpenAI-compat
      - Single docker-compose to spin up
      - Real-world findings expected (model enum, info disclosure, no-auth pull/delete)

    Usage:
        .\demo\run_ollama_demo.ps1                              # stub planner
        .\demo\run_ollama_demo.ps1 -UseLlm                      # OpenAI/Anthropic planner+triage
        .\demo\run_ollama_demo.ps1 -UseLlm -MaxLlmSpendUsd 0.50
        .\demo\run_ollama_demo.ps1 -SkipDockerBootstrap         # assume Ollama already running
        .\demo\run_ollama_demo.ps1 -Model "qwen2.5:0.5b"        # which model to pull (~400 MB)
#>

[CmdletBinding()]
param(
    [switch]$UseLlm,
    [double]$MaxLlmSpendUsd = 1.00,
    [string]$Model = "qwen2.5:0.5b",
    [int]$Port = 11434,
    [switch]$SkipDockerBootstrap,
    [switch]$SkipModelPull
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Compose = Join-Path $PSScriptRoot "docker-compose.ollama.yml"
$ProfilePath = Join-Path $RepoRoot "sample_configs\ollama_agent.json"
$PlanPath = Join-Path $RepoRoot "demo_plan.json"

Write-Host ""
Write-Host "===== ASI v3 demo: scanning LIVE OLLAMA =====" -ForegroundColor Cyan
Write-Host "Target:  http://127.0.0.1:$Port (Ollama)"
Write-Host "Model:   $Model"
Write-Host "LLM:     $UseLlm"
Write-Host ""

# -- 1. Bring up Ollama via docker compose ------------------------------
if (-not $SkipDockerBootstrap) {
    Write-Host "[1/5] Starting Ollama via docker compose..." -ForegroundColor Yellow
    docker compose -f $Compose up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "docker compose up failed. Is Docker Desktop running?" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[1/5] Skipping Docker bootstrap (assuming Ollama is already running)" -ForegroundColor Yellow
}

# -- 2. Wait for /api/version ------------------------------------------
Write-Host "[2/5] Waiting for Ollama API..." -ForegroundColor Yellow
$deadline = (Get-Date).AddSeconds(60)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/version" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ready) {
    Write-Host "Ollama did not respond on $Port within 60s" -ForegroundColor Red
    exit 1
}
$version = (Invoke-RestMethod "http://127.0.0.1:$Port/api/version").version
Write-Host "  Ollama v$version is up" -ForegroundColor Green

# -- 3. Pull a small model so /api/chat actually works -----------------
if (-not $SkipModelPull) {
    Write-Host "[3/5] Pulling small model '$Model' (first run only; ~30-60 s)..." -ForegroundColor Yellow
    docker exec ollama_demo ollama pull $Model
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Model pull failed (continuing -- chat tests may have no model loaded)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[3/5] Skipping model pull" -ForegroundColor Yellow
}

# Patch profile with the chosen port + model
$profileText = Get-Content $ProfilePath -Raw
if ($Port -ne 11434) {
    $profileText = $profileText -replace ':11434', ":$Port"
}
$patched = Join-Path $RepoRoot "demo_ollama_profile.json"
$profileText | Set-Content -Path $patched -Encoding UTF8
$ProfilePath = $patched

# -- 4. Plan + Scan ----------------------------------------------------
Write-Host ""
Write-Host "[4/5] Building TestPlan..." -ForegroundColor Yellow
$PlanArgs = @("plan", "--profile", $ProfilePath, "--out", $PlanPath)
if ($UseLlm) { $PlanArgs += "--llm" }
& python (Join-Path $RepoRoot "cli.py") @PlanArgs

Write-Host ""
Write-Host "[5/5] Running scan-v3 against live Ollama..." -ForegroundColor Yellow
$ScanArgs = @("scan-v3", "--profile", $ProfilePath, "--plan", $PlanPath)
if ($UseLlm) {
    $ScanArgs += "--llm"
    $ScanArgs += "--max-llm-spend-usd"
    $ScanArgs += "$MaxLlmSpendUsd"
}
& python (Join-Path $RepoRoot "cli.py") @ScanArgs
$ScanRc = $LASTEXITCODE

# -- locate reports ---------------------------------------------------
$ResultsDir = Get-ChildItem (Join-Path $RepoRoot "results") -Directory `
              | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($ResultsDir) {
    Write-Host ""
    Write-Host "===== Reports =====" -ForegroundColor Cyan
    Write-Host "  Run dir:  $($ResultsDir.FullName)"
    $Html = Join-Path $ResultsDir.FullName "report.html"
    if (Test-Path $Html) {
        Write-Host "  HTML:     $Html" -ForegroundColor Green
        Write-Host ""
        Write-Host "Opening report.html in default browser..." -ForegroundColor Cyan
        Start-Process $Html
    }
}

if ($ScanRc -eq 1) {
    Write-Host ""
    Write-Host "(exit 1 == CRITICAL vulnerabilities found in the live Ollama instance)" -ForegroundColor Yellow
    Write-Host "    See report.html for which tests fired."
}

Write-Host ""
Write-Host "Ollama still running. Stop it with:" -ForegroundColor DarkGray
Write-Host "  docker compose -f $Compose down -v"
exit 0
