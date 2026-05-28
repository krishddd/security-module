<#
    Dify real-world demo runner.

    What this does:
      1. Clones Dify (if you don't have it) into ..\dify
      2. Brings up Dify via docker compose (7 services, ~3 min first time)
      3. Waits for the web UI on http://localhost
      4. PAUSES for you to do 2 minutes of manual setup in the browser
         (Dify doesn't let us automate the first-admin + create-app flow safely)
      5. Reads back the App API Secret Key from you (or DIFY_APP_TOKEN env var)
      6. Runs scan-v3 against the Dify service API + console API
      7. Opens the report

    Usage:
        .\demo\run_dify_demo.ps1                         # stub planner, walk-through setup
        .\demo\run_dify_demo.ps1 -UseLlm                 # add OpenAI/Anthropic planner+triage
        .\demo\run_dify_demo.ps1 -SkipDockerBootstrap    # if Dify is already running
        .\demo\run_dify_demo.ps1 -DifyToken "app-xxx"    # skip prompt; use this token
#>

[CmdletBinding()]
param(
    [switch]$UseLlm,
    [double]$MaxLlmSpendUsd = 1.00,
    [string]$DifyDir = "",
    [string]$DifyToken = "",
    [switch]$SkipDockerBootstrap
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ProfilePath = Join-Path $RepoRoot "sample_configs\dify_agent.json"
$PlanPath = Join-Path $RepoRoot "demo_plan.json"

if (-not $DifyDir) {
    $DifyDir = Join-Path (Split-Path -Parent (Split-Path -Parent $RepoRoot)) "dify"
}

Write-Host ""
Write-Host "===== ASI v3 demo: scanning LIVE DIFY =====" -ForegroundColor Cyan
Write-Host "Dify dir:  $DifyDir"
Write-Host "LLM:       $UseLlm"
Write-Host ""

# -- 1. Get Dify --------------------------------------------------------
if (-not (Test-Path $DifyDir)) {
    Write-Host "[1/6] Cloning Dify from GitHub..." -ForegroundColor Yellow
    git clone --depth=1 https://github.com/langgenius/dify.git $DifyDir
    if ($LASTEXITCODE -ne 0) { Write-Host "git clone failed" -ForegroundColor Red; exit 1 }
} else {
    Write-Host "[1/6] Dify already cloned at $DifyDir" -ForegroundColor Yellow
}

$DifyDockerDir = Join-Path $DifyDir "docker"

# -- 2. Bootstrap docker compose ----------------------------------------
if (-not $SkipDockerBootstrap) {
    Write-Host "[2/6] Starting Dify (docker compose, ~7 services, can take 3-5 min on first run)..." -ForegroundColor Yellow
    Push-Location $DifyDockerDir
    try {
        if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
        docker compose up -d
        if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (is Docker Desktop running?)" }
    } finally { Pop-Location }
} else {
    Write-Host "[2/6] Skipping Docker bootstrap" -ForegroundColor Yellow
}

# -- 3. Wait for nginx -------------------------------------------------
Write-Host "[3/6] Waiting for Dify on http://127.0.0.1 ..." -ForegroundColor Yellow
$deadline = (Get-Date).AddMinutes(5)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1/console/api/setup" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -in 200,400,401,403) { $ready = $true; break }
    } catch { Start-Sleep -Seconds 3 }
}
if (-not $ready) {
    Write-Host "Dify did not respond within 5 minutes. Check 'docker compose ps' in $DifyDockerDir" -ForegroundColor Red
    exit 1
}
Write-Host "  Dify is up." -ForegroundColor Green

# -- 4. Manual setup prompt --------------------------------------------
if (-not $DifyToken -and -not $env:DIFY_APP_TOKEN) {
    Write-Host ""
    Write-Host "[4/6] MANUAL SETUP STEP (one-time, ~2 minutes)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Open: http://localhost/install" -ForegroundColor White
    Write-Host "    1. Create the first admin account (any email/password)"
    Write-Host "    2. After login, click 'Create from Blank App'"
    Write-Host "    3. Choose 'Chatbot' type"
    Write-Host "    4. Name it 'Demo Chatbot' and create"
    Write-Host "    5. In the editor, click 'Publish' (top right) -> Publish"
    Write-Host "    6. Click 'API Access' in the left sidebar"
    Write-Host "    7. Click 'API Key' -> 'New API Key' -> copy the key starting with 'app-'"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Start-Process "http://localhost/install"
    $DifyToken = Read-Host "Paste the API Secret Key here (starts with 'app-')"
    if (-not $DifyToken) { Write-Host "No token given. Exiting." -ForegroundColor Red; exit 1 }
} elseif ($env:DIFY_APP_TOKEN) {
    $DifyToken = $env:DIFY_APP_TOKEN
    Write-Host "[4/6] Using DIFY_APP_TOKEN from environment" -ForegroundColor Yellow
} else {
    Write-Host "[4/6] Using -DifyToken parameter" -ForegroundColor Yellow
}

$env:DIFY_APP_TOKEN = $DifyToken

# -- 5. Plan + scan -----------------------------------------------------
Write-Host ""
Write-Host "[5/6] Building TestPlan + running scan-v3 against Dify..." -ForegroundColor Yellow
$PlanArgs = @("plan", "--profile", $ProfilePath, "--out", $PlanPath)
if ($UseLlm) { $PlanArgs += "--llm" }
& python (Join-Path $RepoRoot "cli.py") @PlanArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$ScanArgs = @("scan-v3", "--profile", $ProfilePath, "--plan", $PlanPath)
if ($UseLlm) { $ScanArgs += "--llm"; $ScanArgs += "--max-llm-spend-usd"; $ScanArgs += "$MaxLlmSpendUsd" }
& python (Join-Path $RepoRoot "cli.py") @ScanArgs
$ScanRc = $LASTEXITCODE

# -- 6. Open report -----------------------------------------------------
Write-Host ""
Write-Host "[6/6] Opening report..." -ForegroundColor Yellow
$ResultsDir = Get-ChildItem (Join-Path $RepoRoot "results") -Directory `
              | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($ResultsDir) {
    Write-Host ""
    Write-Host "===== Reports =====" -ForegroundColor Cyan
    Write-Host "  Run dir:  $($ResultsDir.FullName)"
    $Html = Join-Path $ResultsDir.FullName "report.html"
    if (Test-Path $Html) {
        Write-Host "  HTML:     $Html" -ForegroundColor Green
        Start-Process $Html
    }
    if (Test-Path (Join-Path $ResultsDir.FullName "report.sarif"))    { Write-Host "  SARIF:    $($ResultsDir.FullName)\report.sarif"    -ForegroundColor Green }
    if (Test-Path (Join-Path $ResultsDir.FullName "report.junit.xml")){ Write-Host "  JUnit:    $($ResultsDir.FullName)\report.junit.xml" -ForegroundColor Green }
}

if ($ScanRc -eq 1) {
    Write-Host ""
    Write-Host "(exit 1 == CRITICAL findings against the live Dify install)" -ForegroundColor Yellow
    Write-Host "    Walk through report.html during the demo -- each finding has a CWE, severity, and remediation."
}

Write-Host ""
Write-Host "Dify is still running. Stop with:" -ForegroundColor DarkGray
Write-Host "  cd `"$DifyDockerDir`"; docker compose down -v"
exit 0
