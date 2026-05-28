#!/usr/bin/env bash
# Real-world demo runner — scans a live Ollama instance.
#
# Usage:
#   bash demo/run_ollama_demo.sh                              # stub planner
#   bash demo/run_ollama_demo.sh --llm                        # planner+triage
#   bash demo/run_ollama_demo.sh --llm --max-llm-spend-usd 0.5
#   bash demo/run_ollama_demo.sh --skip-docker                # if ollama already up
#   bash demo/run_ollama_demo.sh --model llama3.2:1b          # smaller/larger model

set -euo pipefail

USE_LLM=0
MAX_LLM_SPEND_USD=1.00
MODEL="qwen2.5:0.5b"
PORT=11434
SKIP_DOCKER=0
SKIP_PULL=0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$(dirname "${BASH_SOURCE[0]}")/docker-compose.ollama.yml"

while [ $# -gt 0 ]; do
  case "$1" in
    --llm) USE_LLM=1; shift ;;
    --max-llm-spend-usd) MAX_LLM_SPEND_USD="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --skip-docker) SKIP_DOCKER=1; shift ;;
    --skip-pull) SKIP_PULL=1; shift ;;
    -h|--help)
      echo "Usage: $0 [--llm] [--max-llm-spend-usd N] [--model NAME] [--skip-docker] [--skip-pull]"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

PROFILE_PATH="$REPO_ROOT/sample_configs/ollama_agent.json"
PLAN_PATH="$REPO_ROOT/demo_plan.json"

echo ""
echo "===== ASI v3 demo: scanning LIVE OLLAMA ====="
echo "Target:  http://127.0.0.1:$PORT (Ollama)"
echo "Model:   $MODEL"
echo "LLM:     $USE_LLM"
echo ""

if [ "$SKIP_DOCKER" -eq 0 ]; then
  echo "[1/5] Starting Ollama via docker compose..."
  docker compose -f "$COMPOSE" up -d
else
  echo "[1/5] Skipping Docker bootstrap"
fi

echo "[2/5] Waiting for Ollama API..."
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -sf --max-time 2 "http://127.0.0.1:$PORT/api/version" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
if ! curl -sf --max-time 2 "http://127.0.0.1:$PORT/api/version" >/dev/null 2>&1; then
  echo "Ollama did not respond on $PORT within 60s"; exit 1
fi
echo "  Ollama is up"

if [ "$SKIP_PULL" -eq 0 ]; then
  echo "[3/5] Pulling small model '$MODEL'..."
  docker exec ollama_demo ollama pull "$MODEL" || echo "  (pull failed; chat tests may skip)"
else
  echo "[3/5] Skipping model pull"
fi

# Patch port
PATCHED="$REPO_ROOT/demo_ollama_profile.json"
if [ "$PORT" != "11434" ]; then
  sed "s/:11434/:$PORT/g" "$PROFILE_PATH" > "$PATCHED"
else
  cp "$PROFILE_PATH" "$PATCHED"
fi
PROFILE_PATH="$PATCHED"

echo ""; echo "[4/5] Building TestPlan..."
PLAN_ARGS=(plan --profile "$PROFILE_PATH" --out "$PLAN_PATH")
[ "$USE_LLM" = "1" ] && PLAN_ARGS+=(--llm)
( cd "$REPO_ROOT" && python cli.py "${PLAN_ARGS[@]}" )

echo ""; echo "[5/5] Running scan-v3 against live Ollama..."
SCAN_ARGS=(scan-v3 --profile "$PROFILE_PATH" --plan "$PLAN_PATH")
if [ "$USE_LLM" = "1" ]; then
  SCAN_ARGS+=(--llm --max-llm-spend-usd "$MAX_LLM_SPEND_USD")
fi
set +e
( cd "$REPO_ROOT" && python cli.py "${SCAN_ARGS[@]}" )
SCAN_RC=$?
set -e

RESULTS_DIR="$(ls -td "$REPO_ROOT/results/"*/ 2>/dev/null | head -1 || true)"
if [ -n "$RESULTS_DIR" ]; then
  echo ""; echo "===== Reports ====="
  echo "  Run dir:  $RESULTS_DIR"
  [ -f "${RESULTS_DIR}report.html" ] && echo "  HTML:     ${RESULTS_DIR}report.html"
fi
if [ "$SCAN_RC" = "1" ]; then
  echo ""; echo "(exit 1 == CRITICAL vulnerabilities found in live Ollama)"
fi
echo ""
echo "Ollama still running. Stop with: docker compose -f $COMPOSE down -v"
exit 0
