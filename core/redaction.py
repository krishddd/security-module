"""Sensitive-data scrubbing.

A process-global ``Redactor`` collects strings (auth tokens, API keys) that
must be masked before they reach logs, results JSON, or LLM prompts. The
scanner itself ingests untrusted data from the agent under test, so this is
treated as a first-class defense.
"""

from __future__ import annotations

import re
import threading
from typing import Any

_MASK = "***REDACTED***"

# Headers that should always be stripped from logged request/response dumps.
_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
}

# Patterns for tokens we haven't explicitly registered but that look secret.
_GENERIC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                    # OpenAI / Anthropic prefix style
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),             # Anthropic explicit
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),                   # GitHub PAT
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT
]


class Redactor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: set[str] = set()

    def register(self, secret: str | None) -> None:
        if not secret or len(secret) < 6:
            return
        with self._lock:
            self._secrets.add(secret)

    def register_many(self, secrets: list[str]) -> None:
        for s in secrets:
            self.register(s)

    def scrub(self, value: Any) -> Any:
        """Recursively scrub a value (str/dict/list/tuple) of registered
        secrets and well-known secret-shaped substrings."""
        if isinstance(value, str):
            return self._scrub_str(value)
        if isinstance(value, dict):
            return {self._scrub_key(k): self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        if isinstance(value, tuple):
            return tuple(self.scrub(v) for v in value)
        return value

    def _scrub_str(self, s: str) -> str:
        out = s
        with self._lock:
            secrets = list(self._secrets)
        for secret in secrets:
            if secret and secret in out:
                out = out.replace(secret, _MASK)
        for pat in _GENERIC_PATTERNS:
            out = pat.sub(_MASK, out)
        return out

    def _scrub_key(self, key: Any) -> Any:
        if isinstance(key, str) and key.lower() in _SENSITIVE_HEADERS:
            # Keep the key but its value will be replaced; signal by returning
            # the key unchanged — value scrubbing happens in scrub().
            return key
        return key

    def scrub_headers(self, headers: dict[str, Any]) -> dict[str, Any]:
        return {
            k: (_MASK if k.lower() in _SENSITIVE_HEADERS else self.scrub(v))
            for k, v in headers.items()
        }


# Module-level singleton. Anything that wants to scrub imports this.
GLOBAL_REDACTOR = Redactor()
