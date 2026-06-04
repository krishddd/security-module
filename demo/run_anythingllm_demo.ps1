<#
    AnythingLLM real-world demo.

    Demo arc:
      1. Pull + run AnythingLLM (single ~1.5 GB Docker image)
      2. Wait for /api/ping
      3. Pause for ~30 sec manual setup in browser (login + generate API key)
      4. Run `cli.py discover` against the live OpenAPI spec - AUTO-builds the profile
      5. Run `cli.py plan` + `cli.py scan-v3` against the live AnythingLLM
      6. Open the HTML report

    This is the BEST demo: real production tool (54k GitHub stars), single
    container, full auto-discovery via OpenAPI. Nothing pre-built - the
    scanner generates the profile from AnythingLLM's own spec.

    Usage:
        .\demo\run_anythingllm_demo.ps1
        .\demo\run_anythingllm_demo.ps1 -UseLlm -MaxLlmSpendUsd 0.50
        .\demo\run_anythingllm_demo.ps1 -SkipDockerBootstrap -ApiKey "ZxQ..."
#>

[CmdletBinding()]
param(
    [switch]$UseLlm,
    [double]$MaxLlmSpendUsd = 1.00,
    [int]$Port = 3001,
    [switch]$SkipDockerBootstrap,
    [string]$ApiKey = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Compose = Join-Path $PSScriptRoot "docker-compose.anythingllm.yml"
$ProfilePath = Join-Path $RepoRoot "demo_anythingllm_profile.json"
$PlanPath = Join-Path $RepoRoot "demo_plan.json"

Write-Host ""
Write-Host "===== ASI v3 demo: scanning LIVE ANYTHINGLLM =====" -ForegroundColor Cyan
Write-Host "Target:  http://127.0.0.1:$Port (AnythingLLM, 54k GitHub stars)"
Write-Host "LLM:     $UseLlm"
Write-Host ""

# 1. Bring up AnythingLLM
if (-not $SkipDockerBootstrap) {
    Write-Host "[1/6] Starting AnythingLLM via docker compose (single ~1.5 GB image, first pull ~2 min)..." -ForegroundColor Yellow
    docker compose -f $Compose up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "docker compose up failed. Is Docker Desktop running?" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[1/6] Skipping Docker bootstrap (assuming AnythingLLM is already running)" -ForegroundColor Yellow
}

# 2. Wait for /api/ping
Write-Host "[2/6] Waiting for AnythingLLM on http://127.0.0.1:$Port ..." -ForegroundColor Yellow
$deadline = (Get-Date).AddMinutes(3)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/ping" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Seconds 2 }
}
if (-not $ready) {
    Write-Host "AnythingLLM did not respond within 3 minutes. Check 'docker logs anythingllm_demo'" -ForegroundColor Red
    exit 1
}
Write-Host "  AnythingLLM is up." -ForegroundColor Green

# 3. Manual setup prompt
if (-not $ApiKey) {
    Write-Host ""
    Write-Host "[3/6] MANUAL SETUP STEP (~30 seconds, one-time)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Browser is opening to http://localhost:$Port" -ForegroundColor White
    Write-Host ""
    Write-Host "    1. Click 'Get Started' (no account required for local install)"
    Write-Host "    2. Pick any LLM provider (the choice doesn't matter for the scan)"
    Write-Host "    3. Skip / continue through the onboarding (a default workspace is created)"
    Write-Host "    4. Bottom-left settings (gear) -> 'Tools' -> 'Developer API'"
    Write-Host "    5. Click 'Generate new API Key' -> COPY the key"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Start-Process "http://localhost:$Port"
    $ApiKey = Read-Host "Paste the AnythingLLM API Key here (NOT your OpenAI key)"
    if (-not $ApiKey) { Write-Host "No API key given. Exiting." -ForegroundColor Red; exit 1 }
} else {
    Write-Host "[3/6] Using -ApiKey parameter" -ForegroundColor Yellow
}

# Sanity-check: AnythingLLM keys do NOT start with "sk-" (that's OpenAI).
if ($ApiKey.StartsWith("sk-")) {
    Write-Host ""
    Write-Host "ERROR: That looks like an OpenAI key (starts with 'sk-')." -ForegroundColor Red
    Write-Host "       You need the ANYTHINGLLM Developer API key, generated INSIDE the AnythingLLM web UI:"
    Write-Host "         1. Open http://localhost:$Port"
    Write-Host "         2. Complete the onboarding (any LLM provider)"
    Write-Host "         3. Bottom-left gear -> Tools -> Developer API"
    Write-Host "         4. Click 'Generate new API Key' -> copy the long alphanumeric key"
    Write-Host "         5. Re-run this script and paste THAT key"
    exit 1
}

# Register the token with our env-var convention so the adapter uses it.
$env:ANYTHINGLLM_TOKEN = $ApiKey

# 4. Extract OpenAPI spec from container + auto-discover
Write-Host ""
Write-Host "[4/6] Extracting OpenAPI spec from the AnythingLLM container..." -ForegroundColor Yellow
$SpecPath = Join-Path $RepoRoot "demo_anythingllm_openapi.json"
docker cp anythingllm_demo:/app/server/swagger/openapi.json $SpecPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "docker cp failed. Is the container named 'anythingllm_demo' running?" -ForegroundColor Red
    exit 1
}
Write-Host "  Spec written to $SpecPath" -ForegroundColor Green

Write-Host ""
Write-Host "    Running discover against the local spec file..." -ForegroundColor Yellow
& python (Join-Path $RepoRoot "cli.py") discover `
    --url "http://127.0.0.1:$Port" `
    --openapi-url $SpecPath `
    --auth-env ANYTHINGLLM_TOKEN `
    --allow-internal `
    --name anythingllm_demo `
    --risk-tier high `
    --out $ProfilePath
if ($LASTEXITCODE -ne 0) {
    Write-Host "Discover failed." -ForegroundColor Red
    exit 1
}
# Patch the base_url in the generated profile.
# AnythingLLM mounts its REST API under `/api` — every endpoint path in the
# OpenAPI spec is relative to that prefix (e.g. `/v1/auth`, `/v1/workspace/...`).
# We must KEEP the `/api` segment in the base_url, otherwise every request
# hits the SPA fallback handler (which returns the HTML index with 200 OK
# for any unknown path) and the entire scan is bogus.
# Write WITHOUT BOM (pydantic rejects UTF-8 BOM).
$profileText = Get-Content $ProfilePath -Raw
$profileText = $profileText -replace '"base_url":\s*"[^"]+"', "`"base_url`": `"http://127.0.0.1:$Port/api`""

# Resolve a real workspace slug. AnythingLLM's chat endpoints are templated
# (`/v1/workspace/{slug}/chat`); without substitution, requests hit the SPA
# fallback handler (returns the HTML index with 200 OK) and chat tests are
# bogus. Try to find an existing workspace; create one if none exist.
Write-Host "    Resolving workspace slug..." -ForegroundColor DarkGray
try {
    $headers = @{ Authorization = "Bearer $ApiKey"; Accept = "application/json" }
    $wsList = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/workspaces" -Headers $headers -Method Get -TimeoutSec 10
    $slug = $null
    if ($wsList.workspaces -and $wsList.workspaces.Count -gt 0) {
        $slug = $wsList.workspaces[0].slug
        Write-Host "      Using existing workspace: $slug" -ForegroundColor DarkGray
    } else {
        $body = @{ name = "security-demo" } | ConvertTo-Json
        $created = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/workspace/new" `
                    -Headers ($headers + @{ "Content-Type" = "application/json" }) `
                    -Method Post -Body $body -TimeoutSec 15
        $slug = $created.workspace.slug
        Write-Host "      Created workspace: $slug" -ForegroundColor DarkGray
    }
    if ($slug) {
        # Substitute every templated path param the OpenAPI parser captured.
        # All workspace-identifier variants resolve to the same slug; thread
        # gets a sentinel that the chat tester can still POST against.
        $slugTokens = @('slug', 'workspaceId', 'workspaceSlug', 'workspace_slug', 'workspace')
        foreach ($t in $slugTokens) {
            $profileText = $profileText -replace ('\{' + [Regex]::Escape($t) + '\}'), $slug
            $profileText = $profileText -replace ('%7B' + [Regex]::Escape($t) + '%7D'), $slug
        }
        $threadTokens = @('threadSlug', 'thread_slug', 'threadId')
        foreach ($t in $threadTokens) {
            $profileText = $profileText -replace ('\{' + [Regex]::Escape($t) + '\}'), 'default-thread'
            $profileText = $profileText -replace ('%7B' + [Regex]::Escape($t) + '%7D'), 'default-thread'
        }
    }
} catch {
    Write-Host "      WARN: could not resolve workspace slug ($($_.Exception.Message))" -ForegroundColor Yellow
    Write-Host "      Chat tests may target the SPA fallback. Create a workspace in the UI and re-run for best results." -ForegroundColor Yellow
}

[System.IO.File]::WriteAllText($ProfilePath, $profileText, [System.Text.UTF8Encoding]::new($false))

# 5. Plan + Scan
Write-Host ""
Write-Host "[5/6] Building TestPlan + running scan-v3..." -ForegroundColor Yellow
$PlanArgs = @("plan", "--profile", $ProfilePath, "--out", $PlanPath)
if ($UseLlm) { $PlanArgs += "--llm" }
& python (Join-Path $RepoRoot "cli.py") @PlanArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$ScanArgs = @("scan-v3", "--profile", $ProfilePath, "--plan", $PlanPath, "--allow-internal", "--fingerprint", "--yes")
if ($UseLlm) { $ScanArgs += "--llm"; $ScanArgs += "--max-llm-spend-usd"; $ScanArgs += "$MaxLlmSpendUsd" }
& python (Join-Path $RepoRoot "cli.py") @ScanArgs
$ScanRc = $LASTEXITCODE

# 6. Open report
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
    Get-ChildItem $ResultsDir.FullName -File | Where-Object { $_.Name -match '\.(sarif|junit\.xml|json)$' } |
        ForEach-Object { Write-Host "  $($_.Name):  $($_.FullName)" -ForegroundColor Green }
}

if ($ScanRc -eq 1) {
    Write-Host ""
    Write-Host "(exit 1 == CRITICAL findings -- expected against most production agents)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "AnythingLLM is still running. Stop with:" -ForegroundColor DarkGray
Write-Host "  docker compose -f $Compose down -v"
exit 0
