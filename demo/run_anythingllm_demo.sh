#!/usr/bin/env bash
# AnythingLLM real-world demo (bash). See run_anythingllm_demo.ps1 for Windows.
set -euo pipefail

USE_LLM=0
MAX_LLM_SPEND_USD=1.00
PORT=3001
SKIP_DOCKER=0
API_KEY=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$(dirname "${BASH_SOURCE[0]}")/docker-compose.anythingllm.yml"

while [ $# -gt 0 ]; do
  case "$1" in
    --llm) USE_LLM=1; shift ;;
    --max-llm-spend-usd) MAX_LLM_SPEND_USD="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --skip-docker) SKIP_DOCKER=1; shift ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 [--llm] [--max-llm-spend-usd N] [--skip-docker] [--api-key K]"; exit 0 ;;
    *) echo "unknown: $1"; exit 2 ;;
  esac
done

PROFILE_PATH="$REPO_ROOT/demo_anythingllm_profile.json"
PLAN_PATH="$REPO_ROOT/demo_plan.json"

echo ""; echo "===== ASI v3 demo: scanning LIVE ANYTHINGLLM ====="
echo "Target: http://127.0.0.1:$PORT  LLM: $USE_LLM"; echo ""

if [ "$SKIP_DOCKER" -eq 0 ]; then
  echo "[1/6] Starting AnythingLLM via docker compose..."
  docker compose -f "$COMPOSE" up -d
else
  echo "[1/6] Skipping Docker bootstrap"
fi

echo "[2/6] Waiting for AnythingLLM..."
deadline=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -sf --max-time 3 "http://127.0.0.1:$PORT/api/ping" >/dev/null 2>&1; then echo "  up"; break; fi
  sleep 2
done

if [ -z "$API_KEY" ]; then
  echo ""; echo "[3/6] MANUAL SETUP (~30 s):"
  echo "  Open: http://localhost:$PORT"
  echo "    1. Get Started -> pick any LLM provider -> skip onboarding"
  echo "    2. Settings (gear, bottom-left) -> Tools -> Developer API"
  echo "    3. Generate new API Key -> COPY"
  read -rp "Paste API Key: " API_KEY
fi
export ANYTHINGLLM_TOKEN="$API_KEY"

echo ""; echo "[4/6] Auto-discovering via OpenAPI..."
( cd "$REPO_ROOT" && python cli.py discover \
    --url "http://127.0.0.1:$PORT" \
    --openapi-url "http://127.0.0.1:$PORT/api/v1/openapi.json" \
    --auth-env ANYTHINGLLM_TOKEN \
    --allow-internal \
    --name anythingllm_demo \
    --risk-tier high \
    --out "$PROFILE_PATH" )

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
[ "$SCAN_RC" = "1" ] && echo "" && echo "(exit 1 == CRITICAL findings)"

echo ""
echo "AnythingLLM still running. Stop: docker compose -f $COMPOSE down -v"
exit 0
