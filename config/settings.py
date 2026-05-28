"""Platform configuration constants."""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent.parent
RESULTS_DIR = BASE_DIR / "results"
LOGS_DIR = BASE_DIR / "logs"
SAMPLE_CONFIGS_DIR = BASE_DIR / "sample_configs"

# Concurrency — critical for local LLM environments
MAX_CONCURRENT_REQUESTS = int(os.getenv("ASI_MAX_CONCURRENT", "2"))

# HTTP client
DEFAULT_TIMEOUT_S = float(os.getenv("ASI_TIMEOUT_S", "240"))
DEFAULT_BASE_URL = os.getenv("ASI_BASE_URL", "http://localhost:8080")

# Baseline profiling
BASELINE_SAMPLES = int(os.getenv("ASI_BASELINE_SAMPLES", "3"))
BASELINE_QUERY = os.getenv("ASI_BASELINE_QUERY", "What is the total revenue?")
BASELINE_MULTIPLIER = float(os.getenv("ASI_BASELINE_MULTIPLIER", "3.0"))

# OOB callback server
CALLBACK_SERVER_HOST = os.getenv("ASI_CALLBACK_HOST", "127.0.0.1")
CALLBACK_SERVER_PORT = int(os.getenv("ASI_CALLBACK_PORT", "9999"))

# Semantic detection thresholds
SEMANTIC_SIMILARITY_THRESHOLD = float(os.getenv("ASI_SEMANTIC_THRESHOLD", "70.0"))

# Logging
LOG_LEVEL = os.getenv("ASI_LOG_LEVEL", "DEBUG")
LOG_FILE = LOGS_DIR / "debug.log"

# Reporting
REPORT_FORMATS = ["json", "sarif", "junit", "html"]

# ---------------------------------------------------------------------------
# v3: LLM + budget + safety
# ---------------------------------------------------------------------------

# Anthropic API key (resolved lazily; absence is OK when --llm is off).
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Model IDs — ALL model identifiers live here. Never hardcode IDs elsewhere.
# Values are validated against the API at startup in llm/client.py.
LLM_MODEL_PLANNER = os.getenv("ASI_LLM_MODEL_PLANNER", "claude-opus-4-7")
LLM_MODEL_PAYLOAD = os.getenv("ASI_LLM_MODEL_PAYLOAD", "claude-sonnet-4-6")
LLM_MODEL_TRIAGE = os.getenv("ASI_LLM_MODEL_TRIAGE", "claude-sonnet-4-6")

# Provider-specific defaults — used when LLMContext picks a provider
# automatically. The ASI_LLM_MODEL_* env vars above (if explicitly set)
# always win over these.
OPENAI_MODEL_PLANNER = os.getenv("ASI_OPENAI_MODEL_PLANNER", "gpt-4o")
OPENAI_MODEL_PAYLOAD = os.getenv("ASI_OPENAI_MODEL_PAYLOAD", "gpt-4o-mini")
OPENAI_MODEL_TRIAGE  = os.getenv("ASI_OPENAI_MODEL_TRIAGE",  "gpt-4o-mini")

ANTHROPIC_MODEL_PLANNER = os.getenv("ASI_ANTHROPIC_MODEL_PLANNER", "claude-opus-4-7")
ANTHROPIC_MODEL_PAYLOAD = os.getenv("ASI_ANTHROPIC_MODEL_PAYLOAD", "claude-sonnet-4-6")
ANTHROPIC_MODEL_TRIAGE  = os.getenv("ASI_ANTHROPIC_MODEL_TRIAGE",  "claude-sonnet-4-6")

# Prompt-cache breakpoint TTL (seconds). The Anthropic cache TTL is 5 min by
# default; this constant only documents the assumption we depend on.
LLM_CACHE_TTL_S = 300

# Payload synthesis limits
MAX_LLM_PAYLOADS_PER_CATEGORY = int(os.getenv("ASI_MAX_LLM_PAYLOADS", "20"))

# Triage runs only when the structural detector's confidence is in this band.
# Below the band -> clearly blocked, no triage. Above -> clearly exploited.
TRIAGE_AMBIGUITY_BAND: tuple[float, float] = (
    float(os.getenv("ASI_TRIAGE_LOW", "0.4")),
    float(os.getenv("ASI_TRIAGE_HIGH", "0.7")),
)

# Hard budget defaults (CLI flags override).
DEFAULT_MAX_LLM_SPEND_USD = float(os.getenv("ASI_MAX_LLM_SPEND_USD", "2.00"))
DEFAULT_MAX_LLM_CALLS = int(os.getenv("ASI_MAX_LLM_CALLS", "200"))

# Target agent rate limiting (token-bucket inside the adapter).
DEFAULT_RATE_LIMIT_RPM = int(os.getenv("ASI_RATE_LIMIT_RPM", "60"))
DEFAULT_RATE_LIMIT_BURST = int(os.getenv("ASI_RATE_LIMIT_BURST", "10"))

# SSRF guard: lab/CI may flip this on, never default-on in production scans.
ALLOW_INTERNAL_TARGETS_DEFAULT = (
    os.getenv("ASI_ALLOW_INTERNAL", "false").lower() in {"1", "true", "yes"}
)

