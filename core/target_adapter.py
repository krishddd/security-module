"""Target-adapter abstraction (v3).

Decouples the testers from any specific transport. The runner injects one
``TargetAdapter`` subclass per scan; testers call ``invoke``,
``find_endpoints_for``, and (for multi-turn testers) ``invoke_in_session``.

Subclasses in this module:

  RestAgentAdapter      — production HTTP/REST implementation
  GraphQLAgentAdapter   — stub; returns SKIPPED_TRANSPORT
  McpAgentAdapter       — stub; returns SKIPPED_TRANSPORT
  DryRunAdapter         — synthetic responses for `scan --dry-run`

The rate-limit algorithm is **token-bucket** (see RateLimitConfig docstring
in models/agent_profile.py).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from core.redaction import GLOBAL_REDACTOR
from models.agent_profile import (
    AgentProfile,
    AuthScheme,
    EndpointPurpose,
    EndpointSpec,
    HttpMethod,
    RateLimitConfig,
    SessionHandle,
    Transport,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response container (transport-neutral)
# ---------------------------------------------------------------------------


@dataclass
class AdapterResponse:
    """What every adapter returns. Mirrors HttpResponse but transport-agnostic."""

    status_code: int
    data: dict[str, Any]
    latency_ms: float
    ttfb_ms: float
    headers: dict[str, str] = field(default_factory=dict)
    raw_text: str = ""
    rate_limited: bool = False           # True when the request was 429'd past retry budget
    retries_attempted: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


class TransportNotSupportedError(NotImplementedError):
    """Raised by stub adapters in lieu of a SKIPPED_TRANSPORT result. The
    runner catches this and emits a finding with that status."""


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------


class TokenBucket:
    """Async token bucket.

    Holds up to ``capacity`` tokens, refills at ``rate_per_s`` tokens/sec.
    ``acquire()`` blocks until a token is available. ``refund()`` returns a
    spent token to the bucket — used after a 429 so the retry doesn't
    double-count against the budget.
    """

    def __init__(self, capacity: int, rate_per_s: float) -> None:
        self.capacity = max(1, capacity)
        self.rate_per_s = max(0.001, rate_per_s)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_s)
            self._last = now

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                # How long until next token?
                wait = (1 - self._tokens) / self.rate_per_s
            await asyncio.sleep(max(0.01, min(wait, 1.0)))

    async def refund(self) -> None:
        async with self._lock:
            self._tokens = min(self.capacity, self._tokens + 1)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class TargetAdapter(ABC):
    """Abstract base. Every adapter operates against a single AgentProfile."""

    def __init__(self, profile: AgentProfile) -> None:
        self.profile = profile
        self.rate_limit: RateLimitConfig = profile.rate_limit

    # ---- discovery -----------------------------------------------------

    def find_endpoints_for(self, purpose: EndpointPurpose) -> list[EndpointSpec]:
        return self.profile.endpoints_for(purpose)

    # ---- single-turn IO ------------------------------------------------

    @abstractmethod
    async def invoke(
        self, endpoint: EndpointSpec, payload: dict[str, Any] | None = None
    ) -> AdapterResponse:
        ...

    # ---- multi-turn lifecycle -----------------------------------------

    async def open_session(self) -> SessionHandle:
        """Default: a stateless handle. Override for transports with real sessions."""
        return SessionHandle(
            session_id=str(uuid.uuid4()),
            opened_at_ms=int(time.time() * 1000),
        )

    async def close_session(self, handle: SessionHandle) -> None:
        """Default no-op. Override to release transport resources."""
        return None

    async def invoke_in_session(
        self,
        handle: SessionHandle,
        endpoint: EndpointSpec,
        payload: dict[str, Any] | None = None,
    ) -> AdapterResponse:
        """Default: same as ``invoke`` but appends to conversation history."""
        resp = await self.invoke(endpoint, payload)
        handle.conversation.append(
            {"request": GLOBAL_REDACTOR.scrub(payload or {}), "response_status": resp.status_code}
        )
        return resp

    async def reset_session(self) -> None:
        """Clear any persistent adapter-level state. Default: no-op."""
        return None

    # ---- lifecycle -----------------------------------------------------

    async def close(self) -> None:
        """Release transport-level resources (connections, etc.)."""
        return None


# ---------------------------------------------------------------------------
# RestAgentAdapter — production
# ---------------------------------------------------------------------------


class RestAgentAdapter(TargetAdapter):
    """HTTP/REST adapter with token-bucket throttling and 429-aware retries."""

    def __init__(self, profile: AgentProfile, *, timeout_s: float = 60.0) -> None:
        super().__init__(profile)
        self._timeout_s = timeout_s
        rate_per_s = self.rate_limit.requests_per_minute / 60.0
        self._bucket = TokenBucket(capacity=self.rate_limit.burst, rate_per_s=rate_per_s)
        self._client: httpx.AsyncClient | None = None
        self._cookies: httpx.Cookies = httpx.Cookies()
        # Resolve auth token once. The Redactor registers it so any echo of
        # the token from the agent never reaches logs or the LLM triager.
        self._resolved_token: str | None = self._resolve_token()
        if self._resolved_token:
            GLOBAL_REDACTOR.register(self._resolved_token)

    # ---- auth ----------------------------------------------------------

    def _resolve_token(self) -> str | None:
        ac = self.profile.auth
        if ac.scheme == AuthScheme.NONE or not ac.token_env_var:
            return None
        tok = os.environ.get(ac.token_env_var)
        if not tok:
            logger.warning(
                "auth scheme=%s but env var %s is not set — requests will be unauthenticated",
                ac.scheme.value, ac.token_env_var,
            )
        return tok

    def _auth_headers(self) -> dict[str, str]:
        if not self._resolved_token:
            return {}
        ac = self.profile.auth
        return {ac.header_name: f"{ac.header_prefix}{self._resolved_token}".strip()}

    # ---- client lifecycle ---------------------------------------------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=str(self.profile.base_url).rstrip("/"),
                timeout=httpx.Timeout(self._timeout_s, connect=15.0),
                follow_redirects=False,
                cookies=self._cookies,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ---- invoke --------------------------------------------------------

    async def invoke(
        self, endpoint: EndpointSpec, payload: dict[str, Any] | None = None
    ) -> AdapterResponse:
        client = await self._ensure_client()
        retries = 0
        max_retries = self.rate_limit.max_retries_on_429

        while True:
            await self._bucket.acquire()
            start = time.perf_counter()
            try:
                req_headers = self._auth_headers()
                resp = await client.request(
                    endpoint.method.value,
                    endpoint.path,
                    json=payload if endpoint.method != HttpMethod.GET else None,
                    params=payload if endpoint.method == HttpMethod.GET else None,
                    headers=req_headers,
                )
            except httpx.TimeoutException as e:
                latency = (time.perf_counter() - start) * 1000
                logger.warning("invoke timeout %s %s: %s", endpoint.method.value, endpoint.path, e)
                return AdapterResponse(
                    status_code=0, data={"error": f"Timeout: {e}"},
                    latency_ms=latency, ttfb_ms=latency,
                    error=str(e),
                )
            except httpx.HTTPError as e:
                latency = (time.perf_counter() - start) * 1000
                logger.error("invoke error %s %s: %s", endpoint.method.value, endpoint.path, e)
                return AdapterResponse(
                    status_code=0, data={"error": str(e)},
                    latency_ms=latency, ttfb_ms=latency,
                    error=str(e),
                )

            latency = (time.perf_counter() - start) * 1000

            # 429 handling — honor Retry-After, refund the spent token, retry.
            if resp.status_code == 429 and retries < max_retries:
                retries += 1
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                # Exponential backoff floor: 0.5s, 1s, 2s ... clamped to 30s.
                backoff = max(retry_after, min(30.0, 0.5 * (2 ** (retries - 1))))
                logger.info("429 from %s; retry %d/%d after %.2fs", endpoint.path, retries, max_retries, backoff)
                await self._bucket.refund()
                await asyncio.sleep(backoff)
                continue

            # Final response (success, failure, or 429-past-budget)
            try:
                data: dict[str, Any] = resp.json()
                if not isinstance(data, dict):
                    data = {"value": data}
            except Exception:
                data = {"raw": resp.text[:2000]}

            return AdapterResponse(
                status_code=resp.status_code,
                data=data,
                latency_ms=latency,
                ttfb_ms=latency,
                headers=dict(resp.headers),
                raw_text=resp.text[:5000],
                rate_limited=(resp.status_code == 429),
                retries_attempted=retries,
            )

    # ---- session lifecycle (REST contract) ----------------------------

    async def open_session(self) -> SessionHandle:
        """REST sessions are cookie-backed. We start with a fresh jar."""
        self._cookies = httpx.Cookies()
        if self._client and not self._client.is_closed:
            self._client.cookies = self._cookies
        return await super().open_session()

    async def close_session(self, handle: SessionHandle) -> None:
        self._cookies.clear()
        if self._client and not self._client.is_closed:
            self._client.cookies = self._cookies

    async def reset_session(self) -> None:
        """
        REST contract per the plan:
          1. Clear cookie jar.
          2. Re-resolve auth token from env (handles rotation).
          3. Hit the AUTH endpoint if profile declares one;
          4. else any configured ``/reset`` / ``/session`` endpoint;
          5. else no-op with a warning.
        """
        self._cookies.clear()
        # Re-resolve token in case it was rotated.
        new_token = self._resolve_token()
        if new_token and new_token != self._resolved_token:
            GLOBAL_REDACTOR.register(new_token)
            self._resolved_token = new_token

        auth_eps = self.find_endpoints_for(EndpointPurpose.AUTH)
        if auth_eps:
            await self.invoke(auth_eps[0], None)
            return

        reset_candidates = [
            e for e in self.profile.endpoints
            if "reset" in e.path.lower() or "session" in e.path.lower()
        ]
        if reset_candidates:
            await self.invoke(reset_candidates[0], None)
            return

        logger.warning("reset_session: no AUTH or /reset endpoint declared in profile — no-op")


def _parse_retry_after(header: str | None) -> float:
    """Return seconds-to-wait from a Retry-After header (numeric only).
    HTTP-date forms are treated as a default short wait."""
    if not header:
        return 0.0
    try:
        return max(0.0, float(header))
    except ValueError:
        return 1.0  # HTTP-date — pick a sane short default


# ---------------------------------------------------------------------------
# DryRunAdapter
# ---------------------------------------------------------------------------


class DryRunAdapter(TargetAdapter):
    """Used by ``scan --dry-run``. Records intended requests; makes no network calls."""

    def __init__(self, profile: AgentProfile) -> None:
        super().__init__(profile)
        self.recorded_requests: list[dict[str, Any]] = []

    async def invoke(
        self, endpoint: EndpointSpec, payload: dict[str, Any] | None = None
    ) -> AdapterResponse:
        self.recorded_requests.append({
            "method": endpoint.method.value,
            "path": endpoint.path,
            "purpose": endpoint.purpose.value,
            "payload": GLOBAL_REDACTOR.scrub(payload or {}),
        })
        return AdapterResponse(
            status_code=200,
            data={"is_safe": True, "_dry_run": True},
            latency_ms=0.0,
            ttfb_ms=0.0,
        )


# ---------------------------------------------------------------------------
# Transport stubs — return TransportNotSupportedError to surface SKIPPED_TRANSPORT
# ---------------------------------------------------------------------------


class GraphQLAgentAdapter(TargetAdapter):
    async def invoke(self, endpoint: EndpointSpec, payload: dict[str, Any] | None = None) -> AdapterResponse:
        raise TransportNotSupportedError(
            "GraphQL transport not implemented in v2; planned for v2.1. "
            "Testers will be marked SKIPPED_TRANSPORT."
        )


class McpAgentAdapter(TargetAdapter):
    async def invoke(self, endpoint: EndpointSpec, payload: dict[str, Any] | None = None) -> AdapterResponse:
        raise TransportNotSupportedError(
            "MCP transport not implemented in v2; planned for v2.1. "
            "Testers will be marked SKIPPED_TRANSPORT."
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def make_adapter(profile: AgentProfile) -> TargetAdapter:
    """Pick the right adapter for a profile's transport."""
    if profile.transport is Transport.REST:
        return RestAgentAdapter(profile)
    if profile.transport is Transport.GRAPHQL:
        return GraphQLAgentAdapter(profile)
    if profile.transport is Transport.MCP:
        return McpAgentAdapter(profile)
    raise NotImplementedError(f"no adapter for transport {profile.transport!r}")
