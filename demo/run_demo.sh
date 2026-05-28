#!/usr/bin/env bash
# DVAA demo runner — bash (Linux / macOS / WSL).
#
# Usage:
#   bash demo/run_demo.sh                      # default: scan DVAA on :7003
#   bash demo/run_demo.sh --target stub        # scan the in-repo stub agent
#   bash demo/run_demo.sh --llm                # enable Claude planner + triage
#   bash demo/run_demo.sh --port 7001          # scan a different DVAA agent
#   bash demo/run_demo.sh --max-llm-spend-usd 1.00

set -euo pipefail

TARGET=dvaa
PORT=7003
USE_LLM=0
MAX_LLM_SPEND_USD=2.00
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STUB_PID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --llm) USE_LLM=1; shift ;;
    --max-llm-spend-usd) MAX_LLM_SPEND_USD="$2"; shift 2 ;;
    -h|--help)
      sed -n '3,11p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

echo ""
echo "===== ASI v3 Demo ====="
echo "Target: $TARGET  Port: $PORT  LLM: $USE_LLM"
echo ""

wait_for_health() {
  local url="$1"
  local timeout="${2:-60}"
  local deadline=$(( $(date +%s) + timeout ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -sf --max-time 2 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

cleanup() {
  if [ -n "$STUB_PID" ]; then
    kill "$STUB_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

PROFILE_PATH="$REPO_ROOT/sample_configs/dvaa_agent.json"
HEALTH_URL="http://127.0.0.1:$PORT/health"

if [ "$TARGET" = "stub" ]; then
  echo "Target = stub. Starting in-repo FastAPI stub agent in background..."
  STUB_PORT=9100
  HEALTH_URL="http://127.0.0.1:$STUB_PORT/healthz"
  # exec replaces the subshell with python so $! gives the python PID
  # (without exec, $! is the subshell PID and kill leaves uvicorn orphaned).
  ( cd "$REPO_ROOT" && exec python -m uvicorn tests.fixtures.stub_agent.app:app \
      --host 127.0.0.1 --port "$STUB_PORT" --log-level warning >/dev/null 2>&1 ) &
  STUB_PID=$!
  if ! wait_for_health "$HEALTH_URL" 30; then
    echo "Stub did not become healthy"; exit 1
  fi
  PROFILE_PATH="$REPO_ROOT/demo_stub_profile.json"
  (cd "$REPO_ROOT" && python cli.py discover \
      --url "http://127.0.0.1:$STUB_PORT" \
      --openapi-url "http://127.0.0.1:$STUB_PORT/openapi.json" \
      --allow-internal \
      --out "$PROFILE_PATH")
else
  echo "Waiting for DVAA on $HEALTH_URL ..."
  if ! wait_for_health "$HEALTH_URL" 60; then
    echo ""
    echo "[FAIL] DVAA is not reachable on port $PORT."
    echo "       Start it with:"
    echo "         git clone https://github.com/opena2a-org/damn-vulnerable-ai-agent.git"
    echo "         cd damn-vulnerable-ai-agent"
    echo "         docker compose up -d"
    echo "       Then re-run this script."
    exit 1
  fi
  echo "DVAA healthy."
  if [ "$PORT" != "7003" ]; then
    PATCHED="$REPO_ROOT/demo_dvaa_profile.json"
    sed "s/:7003/:$PORT/g" "$PROFILE_PATH" > "$PATCHED"
    PROFILE_PATH="$PATCHED"
  fi
fi

PLAN_PATH="$REPO_ROOT/demo_plan.json"

echo ""
echo "===== Step 1/2: Building TestPlan ====="
PLAN_ARGS=(plan --profile "$PROFILE_PATH" --out "$PLAN_PATH")
[ "$USE_LLM" = "1" ] && PLAN_ARGS+=(--llm)
(cd "$REPO_ROOT" && python cli.py "${PLAN_ARGS[@]}")

echo ""
echo "===== Step 2/2: Running scan-v3 ====="
SCAN_ARGS=(scan-v3 --profile "$PROFILE_PATH" --plan "$PLAN_PATH")
if [ "$USE_LLM" = "1" ]; then
  SCAN_ARGS+=(--llm --max-llm-spend-usd "$MAX_LLM_SPEND_USD")
fi

set +e
(cd "$REPO_ROOT" && python cli.py "${SCAN_ARGS[@]}")
SCAN_RC=$?
set -e

echo ""
echo "===== Done ====="
RESULTS_DIR="$(ls -td "$REPO_ROOT/results/"*/ 2>/dev/null | head -1 || true)"
if [ -n "$RESULTS_DIR" ]; then
  echo "Reports written to:"
  echo "  $RESULTS_DIR"
  if [ -f "${RESULTS_DIR}report.html" ]; then
    echo "  Open in browser: ${RESULTS_DIR}report.html"
  fi
fi

if [ "$SCAN_RC" = "1" ]; then
  echo ""
  echo "(exit 1 == CRITICAL vulnerabilities found — this is the expected DVAA result)"
fi
exit 0
