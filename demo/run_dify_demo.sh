#!/usr/bin/env bash
# Dify real-world demo runner (bash). See run_dify_demo.ps1 for the Windows version.
set -euo pipefail

USE_LLM=0
MAX_LLM_SPEND_USD=1.00
DIFY_DIR=""
DIFY_TOKEN=""
SKIP_DOCKER=0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --llm) USE_LLM=1; shift ;;
    --max-llm-spend-usd) MAX_LLM_SPEND_USD="$2"; shift 2 ;;
    --dify-dir) DIFY_DIR="$2"; shift 2 ;;
    --dify-token) DIFY_TOKEN="$2"; shift 2 ;;
    --skip-docker) SKIP_DOCKER=1; shift ;;
    -h|--help) echo "Usage: $0 [--llm] [--max-llm-spend-usd N] [--dify-dir P] [--dify-token T] [--skip-docker]"; exit 0 ;;
    *) echo "unknown: $1"; exit 2 ;;
  esac
done

[ -z "$DIFY_DIR" ] && DIFY_DIR="$(cd "$REPO_ROOT/../.." && pwd)/dify"
PROFILE_PATH="$REPO_ROOT/sample_configs/dify_agent.json"
PLAN_PATH="$REPO_ROOT/demo_plan.json"

echo ""; echo "===== ASI v3 demo: scanning LIVE DIFY ====="
echo "Dify dir: $DIFY_DIR"; echo "LLM: $USE_LLM"; echo ""

if [ ! -d "$DIFY_DIR" ]; then
  echo "[1/6] Cloning Dify..."
  git clone --depth=1 https://github.com/langgenius/dify.git "$DIFY_DIR"
else
  echo "[1/6] Dify already cloned"
fi

DIFY_DOCKER="$DIFY_DIR/docker"
if [ "$SKIP_DOCKER" -eq 0 ]; then
  echo "[2/6] Starting Dify (docker compose)..."
  (cd "$DIFY_DOCKER" && { [ -f .env ] || cp .env.example .env; } && docker compose up -d)
else
  echo "[2/6] Skipping Docker bootstrap"
fi

echo "[3/6] Waiting for Dify on http://127.0.0.1..."
deadline=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -sf --max-time 3 "http://127.0.0.1/console/api/setup" -o /dev/null 2>&1; then
    echo "  Dify is up"; break
  fi
  sleep 3
done

if [ -z "$DIFY_TOKEN" ] && [ -z "${DIFY_APP_TOKEN:-}" ]; then
  echo ""; echo "[4/6] MANUAL SETUP STEP (~2 min)"
  echo "============================================================"
  echo "  Open: http://localhost/install"
  echo "    1. Create the first admin account"
  echo "    2. Create from Blank App -> Chatbot -> name it -> Create"
  echo "    3. Publish -> Publish"
  echo "    4. API Access (left sidebar) -> New API Key -> copy 'app-...'"
  echo "============================================================"
  read -rp "Paste API Secret Key (app-...): " DIFY_TOKEN
  [ -z "$DIFY_TOKEN" ] && { echo "No token. Exiting."; exit 1; }
elif [ -n "${DIFY_APP_TOKEN:-}" ]; then
  DIFY_TOKEN="$DIFY_APP_TOKEN"
  echo "[4/6] Using DIFY_APP_TOKEN from environment"
fi
export DIFY_APP_TOKEN="$DIFY_TOKEN"

echo ""; echo "[5/6] plan + scan-v3..."
PLAN_ARGS=(plan --profile "$PROFILE_PATH" --out "$PLAN_PATH")
[ "$USE_LLM" = "1" ] && PLAN_ARGS+=(--llm)
( cd "$REPO_ROOT" && python cli.py "${PLAN_ARGS[@]}" )

SCAN_ARGS=(scan-v3 --profile "$PROFILE_PATH" --plan "$PLAN_PATH")
[ "$USE_LLM" = "1" ] && SCAN_ARGS+=(--llm --max-llm-spend-usd "$MAX_LLM_SPEND_USD")
set +e
( cd "$REPO_ROOT" && python cli.py "${SCAN_ARGS[@]}" )
SCAN_RC=$?
set -e

RESULTS_DIR="$(ls -td "$REPO_ROOT/results/"*/ 2>/dev/null | head -1 || true)"
echo ""; echo "===== Reports ====="
[ -n "$RESULTS_DIR" ] && echo "  Run dir: $RESULTS_DIR"
[ -f "${RESULTS_DIR}report.html" ] && echo "  HTML:    ${RESULTS_DIR}report.html"
[ "$SCAN_RC" = "1" ] && echo "" && echo "(exit 1 == CRITICAL findings — expected for an out-of-the-box Dify install)"

echo ""
echo "Dify is still running. Stop with: cd \"$DIFY_DOCKER\" && docker compose down -v"
exit 0
