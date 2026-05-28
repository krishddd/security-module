#!/usr/bin/env bash
# Full demo runner — spins up the in-repo FullVulnAgent + runs all 27 categories.
set -euo pipefail

USE_LLM=0
MAX_LLM_SPEND_USD=1.00
PORT=9200
KEEP_AGENT=0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --llm) USE_LLM=1; shift ;;
    --max-llm-spend-usd) MAX_LLM_SPEND_USD="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --keep-running) KEEP_AGENT=1; shift ;;
    -h|--help)
      echo "Usage: $0 [--llm] [--max-llm-spend-usd N] [--port P] [--keep-running]"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

PROFILE_PATH="$REPO_ROOT/sample_configs/full_vuln_agent.json"
PLAN_PATH="$REPO_ROOT/demo_plan.json"

echo ""
echo "===== ASI v3 FULL Demo ====="
echo "Target: FullVulnAgent (in-repo)  Port: $PORT  LLM: $USE_LLM"
echo ""

AGENT_PID=""
cleanup() {
  if [ "$KEEP_AGENT" -eq 0 ] && [ -n "$AGENT_PID" ]; then
    echo ""; echo "Stopping FullVulnAgent (PID $AGENT_PID)..."
    kill "$AGENT_PID" 2>/dev/null || true
  elif [ "$KEEP_AGENT" -eq 1 ] && [ -n "$AGENT_PID" ]; then
    echo ""; echo "Leaving FullVulnAgent running on PID $AGENT_PID (kill -TERM $AGENT_PID to stop)"
  fi
}
trap cleanup EXIT

echo "[1/4] Starting FullVulnAgent on port $PORT..."
( cd "$REPO_ROOT" && exec python -m uvicorn tests.fixtures.full_vuln_agent.app:app \
    --host 127.0.0.1 --port "$PORT" --log-level warning >/dev/null 2>&1 ) &
AGENT_PID=$!

# Wait for health
deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -sf --max-time 2 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
    echo "Healthy: http://127.0.0.1:$PORT/api/health"; break
  fi
  sleep 0.3
done
if ! curl -sf --max-time 2 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
  echo "FullVulnAgent did not become healthy"; exit 1
fi

# Patch port if non-default
if [ "$PORT" != "9200" ]; then
  PATCHED="$REPO_ROOT/demo_fullvuln_profile.json"
  sed "s/:9200/:$PORT/g" "$PROFILE_PATH" > "$PATCHED"
  PROFILE_PATH="$PATCHED"
fi

echo ""; echo "[2/4] Building TestPlan..."
PLAN_ARGS=(plan --profile "$PROFILE_PATH" --out "$PLAN_PATH")
[ "$USE_LLM" = "1" ] && PLAN_ARGS+=(--llm)
( cd "$REPO_ROOT" && python cli.py "${PLAN_ARGS[@]}" )

echo ""; echo "[3/4] Running scan-v3 (all 27 categories)..."
SCAN_ARGS=(scan-v3 --profile "$PROFILE_PATH" --plan "$PLAN_PATH")
if [ "$USE_LLM" = "1" ]; then
  SCAN_ARGS+=(--llm --max-llm-spend-usd "$MAX_LLM_SPEND_USD")
fi
set +e
( cd "$REPO_ROOT" && python cli.py "${SCAN_ARGS[@]}" )
SCAN_RC=$?
set -e

echo ""; echo "[4/4] Locating reports..."
RESULTS_DIR="$(ls -td "$REPO_ROOT/results/"*/ 2>/dev/null | head -1 || true)"
if [ -n "$RESULTS_DIR" ]; then
  echo ""; echo "===== Reports ====="
  echo "  Run dir:  $RESULTS_DIR"
  for f in report.html report.sarif report.junit.xml report.json; do
    if [ -f "$RESULTS_DIR$f" ]; then echo "  $f"$'\t'"$RESULTS_DIR$f"; fi
  done
fi

if [ "$SCAN_RC" = "1" ]; then
  echo ""; echo "(exit 1 == CRITICAL vulnerabilities found — expected for FullVulnAgent)"
fi
exit 0
