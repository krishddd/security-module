<#
    DVAA demo runner -- Windows PowerShell.

    Usage:
      .\demo\run_demo.ps1                  # default: scan DVAA on :7003
      .\demo\run_demo.ps1 -Target stub     # scan the in-repo stub agent
      .\demo\run_demo.ps1 -UseLlm          # enable Claude planner + triage
      .\demo\run_demo.ps1 -Port 7001       # scan a different DVAA agent (SecureBot)
#>

[CmdletBinding()]
param(
    [ValidateSet("dvaa", "stub")]
    [string]$Target = "dvaa",
    [int]$Port = 7003,
    [switch]$UseLlm,
    [double]$MaxLlmSpendUsd = 2.00
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "===== ASI v3 Demo =====" -ForegroundColor Cyan
Write-Host "Target: $Target  Port: $Port  LLM: $UseLlm"
Write-Host ""

function Wait-ForHealth([string]$Url, [int]$TimeoutSec = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $Url -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
            if ($r.StatusCode -eq 200) { return $true }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    return $false
}

# Resolve profile
$ProfilePath = Join-Path $RepoRoot "sample_configs\dvaa_agent.json"
$HealthUrl = "http://127.0.0.1:$Port/health"
$NeedDvaa = $true

if ($Target -eq "stub") {
    Write-Host "Target = stub. Starting in-repo FastAPI stub agent in background..." -ForegroundColor Yellow
    $StubPort = 9100
    $HealthUrl = "http://127.0.0.1:$StubPort/healthz"
    $StubArgs = @("-m", "uvicorn", "tests.fixtures.stub_agent.app:app",
                  "--host", "127.0.0.1", "--port", "$StubPort", "--log-level", "warning")
    $StubProc = Start-Process -FilePath "python" -ArgumentList $StubArgs -WorkingDirectory $RepoRoot -PassThru -WindowStyle Hidden
    $env:_DEMO_STUB_PID = $StubProc.Id
    # Build a one-off profile via discover
    Write-Host "Discovering stub OpenAPI..."
    if (-not (Wait-ForHealth $HealthUrl 30)) {
        Write-Host "Stub did not become healthy" -ForegroundColor Red
        if ($StubProc -and -not $StubProc.HasExited) { Stop-Process -Id $StubProc.Id -Force }
        exit 1
    }
    $ProfilePath = Join-Path $RepoRoot "demo_stub_profile.json"
    & python (Join-Path $RepoRoot "cli.py") discover `
        --url "http://127.0.0.1:$StubPort" `
        --openapi-url "http://127.0.0.1:$StubPort/openapi.json" `
        --allow-internal `
        --out $ProfilePath
    if ($LASTEXITCODE -ne 0) { exit 1 }
    $NeedDvaa = $false
}

if ($NeedDvaa) {
    Write-Host "Waiting for DVAA on $HealthUrl ..." -ForegroundColor Yellow
    if (-not (Wait-ForHealth $HealthUrl 60)) {
        Write-Host ""
        Write-Host "[FAIL] DVAA is not reachable on port $Port." -ForegroundColor Red
        Write-Host "       Start it with:" -ForegroundColor Yellow
        Write-Host "         git clone https://github.com/opena2a-org/damn-vulnerable-ai-agent.git"
        Write-Host "         cd damn-vulnerable-ai-agent"
        Write-Host "         docker compose up -d"
        Write-Host "       Then re-run this script."
        exit 1
    }
    Write-Host "DVAA healthy." -ForegroundColor Green

    # Patch the port in the pre-built profile if user passed a non-default port.
    if ($Port -ne 7003) {
        $patched = Join-Path $RepoRoot "demo_dvaa_profile.json"
        (Get-Content $ProfilePath -Raw) -replace ':7003', ":$Port" | Set-Content -Path $patched -Encoding UTF8
        $ProfilePath = $patched
    }
}

$PlanPath = Join-Path $RepoRoot "demo_plan.json"

Write-Host ""
Write-Host "===== Step 1/2: Building TestPlan =====" -ForegroundColor Cyan
$PlanArgs = @("plan", "--profile", $ProfilePath, "--out", $PlanPath)
if ($UseLlm) { $PlanArgs += "--llm" }
& python (Join-Path $RepoRoot "cli.py") @PlanArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "===== Step 2/2: Running scan-v3 =====" -ForegroundColor Cyan
$ScanArgs = @("scan-v3", "--profile", $ProfilePath, "--plan", $PlanPath)
if ($UseLlm) {
    $ScanArgs += "--llm"
    $ScanArgs += "--max-llm-spend-usd"
    $ScanArgs += "$MaxLlmSpendUsd"
}
& python (Join-Path $RepoRoot "cli.py") @ScanArgs
$ScanRc = $LASTEXITCODE

# Cleanup stub if we started it
if ($env:_DEMO_STUB_PID) {
    try { Stop-Process -Id $env:_DEMO_STUB_PID -Force -ErrorAction SilentlyContinue } catch {}
    Remove-Item Env:\_DEMO_STUB_PID -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "===== Done =====" -ForegroundColor Cyan
$ResultsDir = Get-ChildItem (Join-Path $RepoRoot "results") -Directory `
              | Sort-Object LastWriteTime -Descending `
              | Select-Object -First 1
if ($ResultsDir) {
    Write-Host "Reports written to:" -ForegroundColor Green
    Write-Host "  $($ResultsDir.FullName)"
    $Html = Join-Path $ResultsDir.FullName "report.html"
    if (Test-Path $Html) {
        Write-Host "  Open in browser: $Html"
    }
}

# scan-v3 exits 1 when CRITICAL findings exist -- that's expected for DVAA.
if ($ScanRc -eq 1) {
    Write-Host ""
    Write-Host "(exit 1 == CRITICAL vulnerabilities found -- this is the expected DVAA result)" -ForegroundColor Yellow
}
exit 0
