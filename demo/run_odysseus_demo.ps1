<#
    Odysseus real-world demo runner.

    Target:  Odysseus  -- self-hosted autonomous AI workspace, 39k+ stars.
             Multi-service docker compose: app + chromadb + searxng + ntfy.
             Real shell + file + MCP tool surface (critical risk profile).

    What this does:
      1. Clones Odysseus into ..\odysseus (if not already there)
      2. Copies .env.example -> .env and injects your OPENAI_API_KEY
      3. docker compose up -d (4 services, ~3-5 min first time)
      4. Waits for the app on http://localhost:7000
      5. Prints the temp admin password from container logs
      6. PAUSES for you to log in, change password, and generate an API token
      7. Reads back the token
      8. Tries auto-discover via /openapi.json; falls back to pre-built profile
      9. Runs scan-v3 against the live Odysseus
     10. Opens the report

    Usage:
        .\demo\run_odysseus_demo.ps1
        .\demo\run_odysseus_demo.ps1 -UseLlm -MaxLlmSpendUsd 0.50
        .\demo\run_odysseus_demo.ps1 -SkipDockerBootstrap -Token "od_xxx"
#>

[CmdletBinding()]
param(
    [switch]$UseLlm,
    [double]$MaxLlmSpendUsd = 1.00,
    [int]$Port = 7000,
    [string]$OdysseusDir = "",
    [string]$Token = "",
    [switch]$SkipDockerBootstrap,
    [switch]$ForceFallbackProfile
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$FallbackProfile = Join-Path $RepoRoot "sample_configs\odysseus_agent.json"
$AutoProfilePath = Join-Path $RepoRoot "demo_odysseus_profile.json"
$PlanPath = Join-Path $RepoRoot "demo_plan.json"

if (-not $OdysseusDir) {
    $OdysseusDir = Join-Path (Split-Path -Parent (Split-Path -Parent $RepoRoot)) "odysseus"
}

Write-Host ""
Write-Host "===== ASI v3 demo: scanning LIVE ODYSSEUS =====" -ForegroundColor Cyan
Write-Host "Odysseus dir: $OdysseusDir"
Write-Host "Target:       http://127.0.0.1:$Port"
Write-Host "LLM:          $UseLlm"
Write-Host ""

# 1. Get Odysseus
if (-not (Test-Path $OdysseusDir)) {
    Write-Host "[1/7] Cloning Odysseus from GitHub..." -ForegroundColor Yellow
    git clone --depth=1 https://github.com/pewdiepie-archdaemon/odysseus.git $OdysseusDir
    if ($LASTEXITCODE -ne 0) { Write-Host "git clone failed" -ForegroundColor Red; exit 1 }
} else {
    Write-Host "[1/7] Odysseus already cloned at $OdysseusDir" -ForegroundColor Yellow
}

# 2. Configure .env
Write-Host "[2/7] Configuring .env..." -ForegroundColor Yellow
Push-Location $OdysseusDir
try {
    if (-not (Test-Path ".env")) {
        if (Test-Path ".env.example") {
            Copy-Item ".env.example" ".env"
            Write-Host "  Created .env from .env.example"
        } else {
            Write-Host "  WARNING: no .env.example found. Creating minimal .env." -ForegroundColor Yellow
            "ODYSSEUS_ADMIN_PASSWORD=demo_admin_pw_change_me" | Set-Content ".env"
        }
    }

    # Inject OPENAI_API_KEY from the scanner's own .env if present
    $scannerEnv = Join-Path $RepoRoot ".env"
    if (Test-Path $scannerEnv) {
        $openaiLine = Get-Content $scannerEnv | Where-Object { $_ -match "^OPENAI_API_KEY=" } | Select-Object -First 1
        if ($openaiLine) {
            $envContent = Get-Content ".env" -Raw
            if ($envContent -notmatch "(?m)^OPENAI_API_KEY=sk-") {
                $envContent = ($envContent -replace "(?m)^OPENAI_API_KEY=.*$", "") + "`n$openaiLine"
                [System.IO.File]::WriteAllText(".env", $envContent, [System.Text.UTF8Encoding]::new($false))
                Write-Host "  Injected OPENAI_API_KEY from scanner .env" -ForegroundColor Green
            } else {
                Write-Host "  OPENAI_API_KEY already set in Odysseus .env" -ForegroundColor Green
            }
        }
    }
} finally { Pop-Location }

# 3. Bring up docker compose
if (-not $SkipDockerBootstrap) {
    Write-Host "[3/7] Starting Odysseus stack (4 services, can take 3-5 min on first run)..." -ForegroundColor Yellow
    Push-Location $OdysseusDir
    try {
        docker compose up -d --build
        if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (is Docker Desktop running?)" }
    } finally { Pop-Location }
} else {
    Write-Host "[3/7] Skipping Docker bootstrap" -ForegroundColor Yellow
}

# 4. Wait for Odysseus on port 7000
#    Poll /api/health (returns 200 with JSON) -- the root path returns 302
#    which PowerShell's Invoke-WebRequest auto-follow handles inconsistently.
Write-Host "[4/7] Waiting for Odysseus on http://127.0.0.1:$Port/api/health ..." -ForegroundColor Yellow
$deadline = (Get-Date).AddMinutes(5)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { Start-Sleep -Seconds 3 }
}
if (-not $ready) {
    Write-Host "Odysseus did not respond on /api/health within 5 minutes. Check 'docker compose logs' in $OdysseusDir" -ForegroundColor Red
    exit 1
}
Write-Host "  Odysseus is up." -ForegroundColor Green

# 5. Get the temp admin password from container logs
if (-not $Token) {
    Write-Host "[5/7] Looking for admin password in container logs..." -ForegroundColor Yellow
    $logs = docker compose -f (Join-Path $OdysseusDir "docker-compose.yml") logs odysseus 2>$null
    $tempPw = ($logs | Select-String -Pattern "(temporary password|admin password|temp_password)" -Context 0,2 | Select-Object -First 1)
    if ($tempPw) {
        Write-Host "  Found in logs:" -ForegroundColor Green
        Write-Host "    $tempPw" -ForegroundColor White
    } else {
        Write-Host "  Could not auto-detect temp password. Run:" -ForegroundColor Yellow
        Write-Host "    docker compose logs odysseus | Select-String password"
        Write-Host "  (or check the container logs in Docker Desktop)"
    }
}

# 6. Manual login + token generation
if (-not $Token) {
    Write-Host ""
    Write-Host "[6/7] MANUAL SETUP STEP (~2 minutes, one-time)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Browser opens to http://localhost:$Port" -ForegroundColor White
    Write-Host ""
    Write-Host "    1. Log in as admin (temp password is above, or check logs)"
    Write-Host "    2. Change the password when prompted"
    Write-Host "    3. Go to Settings -> API Tokens (or Admin -> Tokens)"
    Write-Host "    4. Create a new API token"
    Write-Host "    5. Copy the token value"
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Start-Process "http://localhost:$Port"
    $Token = Read-Host "Paste the Odysseus API Token here"
    if (-not $Token) { Write-Host "No token given. Exiting." -ForegroundColor Red; exit 1 }
}

# Reject OpenAI-key shape
if ($Token.StartsWith("sk-")) {
    Write-Host ""
    Write-Host "ERROR: that looks like an OpenAI key ('sk-...'). Need the ODYSSEUS API token from the admin UI." -ForegroundColor Red
    exit 1
}

$env:ODYSSEUS_TOKEN = $Token

# 7. Try auto-discover via OpenAPI; fall back to pre-built profile
Write-Host ""
Write-Host "[7/7] Discovering Odysseus API ..." -ForegroundColor Yellow

$ProfilePath = $null
if (-not $ForceFallbackProfile) {
    try {
        # Odysseus serves OpenAPI at /api/openapi.json -- auth-required.
        # Fetch with the token; if JSON, run discover against a local copy.
        $hdrs = @{ Authorization = "Bearer $Token" }
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/openapi.json" `
              -Headers $hdrs -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -eq 200 -and $r.Content.StartsWith("{")) {
            Write-Host "  /api/openapi.json found -- saving + running auto-discover" -ForegroundColor Green
            $specPath = Join-Path $RepoRoot "demo_odysseus_openapi.json"
            [System.IO.File]::WriteAllText($specPath, $r.Content, [System.Text.UTF8Encoding]::new($false))

            & python (Join-Path $RepoRoot "cli.py") discover `
                --url "http://127.0.0.1:$Port" `
                --openapi-url $specPath `
                --auth-env ODYSSEUS_TOKEN `
                --allow-internal `
                --name odysseus_local `
                --risk-tier critical `
                --out $AutoProfilePath
            if ($LASTEXITCODE -eq 0) {
                $profileText = Get-Content $AutoProfilePath -Raw
                $profileText = $profileText -replace '"base_url":\s*"[^"]+"', "`"base_url`": `"http://127.0.0.1:$Port`""
                [System.IO.File]::WriteAllText($AutoProfilePath, $profileText, [System.Text.UTF8Encoding]::new($false))
                $ProfilePath = $AutoProfilePath
                Write-Host "  Auto-discovered profile at $AutoProfilePath" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  Could not fetch /api/openapi.json (token may lack scope or endpoint differs). Using fallback profile." -ForegroundColor Yellow
    }
}

if (-not $ProfilePath) {
    $ProfilePath = $FallbackProfile
    Write-Host "  Using pre-built profile: $ProfilePath" -ForegroundColor Yellow
    if ($Port -ne 7000) {
        $profileText = Get-Content $ProfilePath -Raw
        $profileText = $profileText -replace ':7000', ":$Port"
        $patched = Join-Path $RepoRoot "demo_odysseus_profile.json"
        [System.IO.File]::WriteAllText($patched, $profileText, [System.Text.UTF8Encoding]::new($false))
        $ProfilePath = $patched
    }
}

# Plan + scan
Write-Host ""
Write-Host "Building TestPlan + running scan-v3 against Odysseus..." -ForegroundColor Yellow
$PlanArgs = @("plan", "--profile", $ProfilePath, "--out", $PlanPath)
if ($UseLlm) { $PlanArgs += "--llm" }
& python (Join-Path $RepoRoot "cli.py") @PlanArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$ScanArgs = @("scan-v3", "--profile", $ProfilePath, "--plan", $PlanPath, "--allow-internal", "--fingerprint", "--yes")
if ($UseLlm) { $ScanArgs += "--llm"; $ScanArgs += "--max-llm-spend-usd"; $ScanArgs += "$MaxLlmSpendUsd" }
& python (Join-Path $RepoRoot "cli.py") @ScanArgs
$ScanRc = $LASTEXITCODE

# Open report
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
    Write-Host "(exit 1 == CRITICAL findings -- expected against an agent with shell/file/MCP capabilities)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Odysseus is still running. Stop with:" -ForegroundColor DarkGray
Write-Host "  cd `"$OdysseusDir`"; docker compose down -v"
exit 0
