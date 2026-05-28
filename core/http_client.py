"""
Async HTTP client with semaphore-controlled concurrency, TTFB tracking, and SSE support.
Designed for local LLM environments where uncontrolled concurrency crashes Ollama.
"""

from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator

import httpx

from config.settings import MAX_CONCURRENT_REQUESTS, DEFAULT_TIMEOUT_S, LOG_FILE, LOGS_DIR

logger = logging.getLogger(__name__)


@dataclass
class HttpResponse:
    """Structured HTTP response with timing metrics."""
    status_code: int
    data: dict[str, Any]
    latency_ms: float
    ttfb_ms: float
    headers: dict[str, str] = field(default_factory=dict)
    raw_text: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


@dataclass
class SSEEvent:
    """A single Server-Sent Event."""
    event: str = ""
    data: str = ""
    id: str = ""
    timestamp_ms: float = 0.0


class AsyncHttpClient:
    """
    Semaphore-wrapped async HTTP client with TTFB tracking.
    Controls concurrency to protect local LLM instances.
    """

    def __init__(
        self,
        base_url: str,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_concurrent: int = MAX_CONCURRENT_REQUESTS,
        auth_headers: dict[str, str] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._auth_headers = auth_headers or {}
        self._client: httpx.AsyncClient | None = None
        self._setup_logging()

    def _setup_logging(self) -> None:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
        ))
        logger.addHandler(fh)

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout_s, connect=30.0),
                headers={**self._auth_headers},
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def post_json(
        self, path: str, payload: dict[str, Any] | None = None
    ) -> HttpResponse:
        """POST JSON with semaphore control and TTFB tracking."""
        async with self._semaphore:
            client = await self._ensure_client()
            url = path
            logger.debug(f"POST {self.base_url}{path} payload={payload}")

            start = time.perf_counter()
            ttfb = 0.0
            try:
                resp = await client.post(url, json=payload or {})
                ttfb = (time.perf_counter() - start) * 1000
                latency = (time.perf_counter() - start) * 1000

                try:
                    data = resp.json()
                except Exception:
                    data = {"raw": resp.text[:2000]}

                result = HttpResponse(
                    status_code=resp.status_code,
                    data=data,
                    latency_ms=latency,
                    ttfb_ms=ttfb,
                    headers=dict(resp.headers),
                    raw_text=resp.text[:5000],
                )
                logger.debug(
                    f"POST {path} -> {resp.status_code} "
                    f"latency={latency:.0f}ms ttfb={ttfb:.0f}ms"
                )
                return result

            except httpx.TimeoutException as e:
                latency = (time.perf_counter() - start) * 1000
                logger.warning(f"POST {path} timeout after {latency:.0f}ms: {e}")
                return HttpResponse(
                    status_code=0, data={"error": f"Timeout: {e}"},
                    latency_ms=latency, ttfb_ms=ttfb,
                )
            except httpx.HTTPError as e:
                latency = (time.perf_counter() - start) * 1000
                logger.error(f"POST {path} error: {e}")
                return HttpResponse(
                    status_code=0, data={"error": str(e)},
                    latency_ms=latency, ttfb_ms=ttfb,
                )

    async def get_json(self, path: str, params: dict | None = None) -> HttpResponse:
        """GET JSON with semaphore control and TTFB tracking."""
        async with self._semaphore:
            client = await self._ensure_client()
            logger.debug(f"GET {self.base_url}{path} params={params}")

            start = time.perf_counter()
            ttfb = 0.0
            try:
                resp = await client.get(path, params=params)
                ttfb = (time.perf_counter() - start) * 1000
                latency = (time.perf_counter() - start) * 1000

                try:
                    data = resp.json()
                except Exception:
                    data = {"raw": resp.text[:2000]}

                result = HttpResponse(
                    status_code=resp.status_code,
                    data=data,
                    latency_ms=latency,
                    ttfb_ms=ttfb,
                    headers=dict(resp.headers),
                    raw_text=resp.text[:5000],
                )
                logger.debug(f"GET {path} -> {resp.status_code} latency={latency:.0f}ms")
                return result

            except httpx.TimeoutException as e:
                latency = (time.perf_counter() - start) * 1000
                logger.warning(f"GET {path} timeout: {e}")
                return HttpResponse(
                    status_code=0, data={"error": f"Timeout: {e}"},
                    latency_ms=latency, ttfb_ms=ttfb,
                )
            except httpx.HTTPError as e:
                latency = (time.perf_counter() - start) * 1000
                logger.error(f"GET {path} error: {e}")
                return HttpResponse(
                    status_code=0, data={"error": str(e)},
                    latency_ms=latency, ttfb_ms=ttfb,
                )

    async def delete_json(
        self, path: str, payload: dict[str, Any] | None = None
    ) -> HttpResponse:
        """DELETE with JSON body."""
        async with self._semaphore:
            client = await self._ensure_client()
            start = time.perf_counter()
            ttfb = 0.0
            try:
                resp = await client.request(
                    "DELETE", path, json=payload or {}
                )
                ttfb = (time.perf_counter() - start) * 1000
                latency = (time.perf_counter() - start) * 1000
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw": resp.text[:2000]}
                return HttpResponse(
                    status_code=resp.status_code, data=data,
                    latency_ms=latency, ttfb_ms=ttfb,
                    headers=dict(resp.headers), raw_text=resp.text[:5000],
                )
            except Exception as e:
                latency = (time.perf_counter() - start) * 1000
                return HttpResponse(
                    status_code=0, data={"error": str(e)},
                    latency_ms=latency, ttfb_ms=ttfb,
                )

    async def get_sse(
        self, path: str, params: dict | None = None
    ) -> AsyncGenerator[SSEEvent, None]:
        """Stream SSE events with TTFB tracking per event."""
        async with self._semaphore:
            client = await self._ensure_client()
            start = time.perf_counter()
            first_event = True

            try:
                async with client.stream("GET", path, params=params) as resp:
                    buffer = ""
                    async for chunk in resp.aiter_text():
                        if first_event:
                            ttfb = (time.perf_counter() - start) * 1000
                            logger.debug(f"SSE {path} TTFB={ttfb:.0f}ms")
                            first_event = False

                        buffer += chunk
                        while "\n\n" in buffer:
                            event_str, buffer = buffer.split("\n\n", 1)
                            event = SSEEvent(
                                timestamp_ms=(time.perf_counter() - start) * 1000
                            )
                            for line in event_str.split("\n"):
                                if line.startswith("event:"):
                                    event.event = line[6:].strip()
                                elif line.startswith("data:"):
                                    event.data = line[5:].strip()
                                elif line.startswith("id:"):
                                    event.id = line[3:].strip()
                            yield event
            except Exception as e:
                logger.error(f"SSE {path} error: {e}")

    async def post_sse(
        self, path: str, payload: dict[str, Any] | None = None
    ) -> AsyncGenerator[SSEEvent, None]:
        """Stream SSE events from a POST endpoint with TTFB tracking."""
        async with self._semaphore:
            client = await self._ensure_client()
            start = time.perf_counter()
            first_event = True

            try:
                async with client.stream("POST", path, json=payload or {}) as resp:
                    buffer = ""
                    async for chunk in resp.aiter_text():
                        if first_event:
                            ttfb = (time.perf_counter() - start) * 1000
                            logger.debug(f"SSE POST {path} TTFB={ttfb:.0f}ms")
                            first_event = False

                        buffer += chunk
                        while "\n\n" in buffer:
                            event_str, buffer = buffer.split("\n\n", 1)
                            event = SSEEvent(
                                timestamp_ms=(time.perf_counter() - start) * 1000
                            )
                            for line in event_str.split("\n"):
                                if line.startswith("event:"):
                                    event.event = line[6:].strip()
                                elif line.startswith("data:"):
                                    event.data = line[5:].strip()
                                elif line.startswith("id:"):
                                    event.id = line[3:].strip()
                            yield event
            except Exception as e:
                logger.error(f"SSE POST {path} error: {e}")
