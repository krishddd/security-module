"""
Local Out-of-Band Application Security Testing (OAST) callback server.
Used by ASI05 to definitively prove code execution via OOB interactions.
"""

from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from aiohttp import web

from config.settings import CALLBACK_SERVER_HOST, CALLBACK_SERVER_PORT

logger = logging.getLogger(__name__)


@dataclass
class CallbackRecord:
    """Records an incoming OOB callback."""
    timestamp: float
    method: str
    path: str
    headers: dict[str, str]
    body: str
    query: dict[str, str]
    source_ip: str


class CallbackServer:
    """
    Lightweight OAST server that records all incoming HTTP requests.
    ASI05 payloads point to http://localhost:9999/asi05/<test_id> to prove execution.
    """

    def __init__(
        self,
        host: str = CALLBACK_SERVER_HOST,
        port: int = CALLBACK_SERVER_PORT,
    ):
        self.host = host
        self.port = port
        self.records: list[CallbackRecord] = []
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    async def start(self) -> None:
        self._app = web.Application()
        self._app.router.add_route("*", "/{path_info:.*}", self._handle_request)
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        try:
            await self._site.start()
            logger.info(f"OOB callback server listening on {self.host}:{self.port}")
        except OSError as e:
            logger.warning(f"Could not start callback server: {e}")

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            logger.info("OOB callback server stopped")

    async def _handle_request(self, request: web.Request) -> web.Response:
        body = ""
        try:
            body = await request.text()
        except Exception:
            pass

        record = CallbackRecord(
            timestamp=time.time(),
            method=request.method,
            path=str(request.path),
            headers=dict(request.headers),
            body=body,
            query=dict(request.query),
            source_ip=request.remote or "",
        )
        self.records.append(record)
        logger.info(f"OOB callback received: {request.method} {request.path}")
        return web.Response(text="OK")

    def get_records_for_test(self, test_id: str) -> list[CallbackRecord]:
        """Get all callbacks matching a specific test ID in the path."""
        return [r for r in self.records if test_id in r.path]

    def clear(self) -> None:
        self.records.clear()

    @property
    def callback_url(self) -> str:
        return f"http://{self.host}:{self.port}"
