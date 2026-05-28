<#
    Full demo runner -- spins up the in-repo FullVulnAgent + runs all 27 categories.

    Usage:
        .\demo\run_full_demo.ps1                   # stub planner (no LLM cost)
        .\demo\run_full_demo.ps1 -UseLlm           # OpenAI/Anthropic planner+triage
        .\demo\run_full_demo.ps1 -UseLlm -MaxLlmSpendUsd 0.50
#>

[CmdletBinding()]
param(
    [switch]$UseLlm,
    [double]$MaxLlmSpendUsd = 1.00,
    [int]$Port = 9200,
    [switch]$KeepAgentRunning
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ProfilePath = Join-Path $RepoRoot "sample_configs\full_vuln_agent.json"
$PlanPath = Join-Path $RepoRoot "demo_plan.json"

Write-Host ""
Write-Host "===== ASI v3 FULL Demo =====" -ForegroundColor Cyan
Write-Host "Target:  FullVulnAgent (in-repo)  Port: $Port  LLM: $UseLlm"
Write-Host ""

# -- 1. Start the agent ---------------------------------------------------
Write-Host "[1/4] Starting FullVulnAgent on port $Port..." -ForegroundColor Yellow
$StubArgs = @(
    "-m", "uvicorn",
    "tests.fixtures.full_vuln_agent.app:app",
    "--host", "127.0.0.1", "--port", "$Port",
    "--log-level", "warning"
)
$AgentProc = Start-Process -FilePath "python" -ArgumentList $StubArgs `
              -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden

function Stop-Agent {
    if (-not $script:KeepAgentRunning -and $script:AgentProc -and -not $script:AgentProc.HasExited) {
        try { Stop-Process -Id $script:AgentProc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
}

# Wait for /api/health
$deadline = (Get-Date).AddSeconds(30)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/health" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Milliseconds 300 }
}
if (-not $ready) {
    Stop-Agent
    Write-Host "FullVulnAgent did not become healthy" -ForegroundColor Red
    exit 1
}
Write-Host "Healthy: http://127.0.0.1:$Port/api/health" -ForegroundColor Green

# Patch profile port if user changed it
if ($Port -ne 9200) {
    $patched = Join-Path $RepoRoot "demo_fullvuln_profile.json"
    (Get-Content $ProfilePath -Raw) -replace ':9200', ":$Port" | Set-Content -Path $patched -Encoding UTF8
    $ProfilePath = $patched
}

try {
    # -- 2. Build plan ----------------------------------------------------
    Write-Host ""
    Write-Host "[2/4] Building TestPlan..." -ForegroundColor Yellow
    $PlanArgs = @("plan", "--profile", $ProfilePath, "--out", $PlanPath)
    if ($UseLlm) { $PlanArgs += "--llm" }
    & python (Join-Path $RepoRoot "cli.py") @PlanArgs
    if ($LASTEXITCODE -ne 0) { throw "plan command failed (exit $LASTEXITCODE)" }

    # -- 3. Scan ----------------------------------------------------------
    Write-Host ""
    Write-Host "[3/4] Running scan-v3 (all 27 categories)..." -ForegroundColor Yellow
    $ScanArgs = @("scan-v3", "--profile", $ProfilePath, "--plan", $PlanPath)
    if ($UseLlm) {
        $ScanArgs += "--llm"
        $ScanArgs += "--max-llm-spend-usd"
        $ScanArgs += "$MaxLlmSpendUsd"
    }
    & python (Join-Path $RepoRoot "cli.py") @ScanArgs
    $ScanRc = $LASTEXITCODE

    # -- 4. Locate reports ------------------------------------------------
    Write-Host ""
    Write-Host "[4/4] Locating reports..." -ForegroundColor Yellow
    $ResultsDir = Get-ChildItem (Join-Path $RepoRoot "results") -Directory `
                  | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($ResultsDir) {
        Write-Host ""
        Write-Host "===== Reports =====" -ForegroundColor Cyan
        Write-Host "  Run dir:  $($ResultsDir.FullName)"
        $Html = Join-Path $ResultsDir.FullName "report.html"
        $Sarif = Join-Path $ResultsDir.FullName "report.sarif"
        $JUnit = Join-Path $ResultsDir.FullName "report.junit.xml"
        $Json = Join-Path $ResultsDir.FullName "report.json"
        if (Test-Path $Html)  { Write-Host "  HTML:     $Html" -ForegroundColor Green }
        if (Test-Path $Sarif) { Write-Host "  SARIF:    $Sarif" -ForegroundColor Green }
        if (Test-Path $JUnit) { Write-Host "  JUnit:    $JUnit" -ForegroundColor Green }
        if (Test-Path $Json)  { Write-Host "  JSON:     $Json"  -ForegroundColor Green }
        if (Test-Path $Html) {
            Write-Host ""
            Write-Host "Opening report.html in default browser..." -ForegroundColor Cyan
            Start-Process $Html
        }
    }

    if ($ScanRc -eq 1) {
        Write-Host ""
        Write-Host "(exit 1 == CRITICAL vulnerabilities found -- expected for FullVulnAgent)" -ForegroundColor Yellow
    }
} finally {
    if (-not $KeepAgentRunning) {
        Write-Host ""
        Write-Host "Stopping FullVulnAgent..."
        Stop-Agent
    } else {
        Write-Host ""
        Write-Host "Leaving FullVulnAgent running (PID $($AgentProc.Id)). Stop with: Stop-Process -Id $($AgentProc.Id)" -ForegroundColor Yellow
    }
}
exit 0
