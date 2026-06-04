"""Preflight verification for v3 agent profiles.

Runs a series of rubric-graded checks against the live target before any
security tests fire. Provides visible proof that the scanner is actually
talking to the agent — stale tokens, restarted containers, or wrong
endpoints surface here instead of inside a tester.

Owners:
  - SSRF enforcement is NOT done here. ``core/ssrf_guard.assert_url_safe``
    runs once at CLI startup against ``profile.base_url``.
  - All I/O goes through ``RestAgentAdapter.invoke`` so rate-limits, retries,
    and token redaction apply uniformly.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from models.agent_profile import (
    AgentProfile,
    AuthScheme,
    EndpointPurpose,
    EndpointSpec,
    HttpMethod,
)

logger = logging.getLogger(__name__)


PreflightStatus = Literal["green", "warn", "hard_stop", "skipped"]
ClassificationPath = Literal["llm", "regex"]


@dataclass
class PreflightCheck:
    name: str
    status: PreflightStatus
    latency_ms: float = 0.0
    evidence: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def icon(self) -> str:
        return {"green": "OK", "warn": "WARN", "hard_stop": "FAIL", "skipped": "SKIP"}[self.status]


@dataclass
class PreflightResult:
    profile_name: str
    base_url: str
    checks: list[PreflightCheck] = field(default_factory=list)
    overall: PreflightStatus = "green"
    chat_excerpt: str = ""

    def has_hard_stop(self) -> bool:
        return any(c.status == "hard_stop" for c in self.checks)

    def has_warn(self) -> bool:
        return any(c.status == "warn" for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "base_url": self.base_url,
            "overall": self.overall,
            "chat_excerpt": self.chat_excerpt,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status,
                    "latency_ms": round(c.latency_ms, 2),
                    "evidence": c.evidence,
                    "detail": c.detail,
                }
                for c in self.checks
            ],
        }


class PreflightFailure(RuntimeError):
    """Raised when a HARD-STOP check fails. Caller decides exit code."""

    def __init__(self, result: PreflightResult, failed_check: str) -> None:
        super().__init__(f"preflight HARD-STOP on {failed_check}")
        self.result = result
        self.failed_check = failed_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _key_looks_real(value: str | None) -> bool:
    """Reject empty/placeholder env values. Mirrors llm.context._key_is_real
    but tolerant of shorter API tokens (some agents use 16-char keys)."""
    if not value:
        return False
    s = value.strip()
    if len(s) < 8:
        return False
    if "xxxx" in s.lower() or "placeholder" in s.lower():
        return False
    if s.count("*") > len(s) / 2:
        return False
    return True


def _pick_chat_endpoint(profile: AgentProfile) -> EndpointSpec | None:
    """Pick the endpoint most likely to be the actual chat-input route.

    Several endpoints get classified as CHAT purpose (admin listings, exports,
    threads, etc.). Rank them so the action route wins:
      1. POST whose path ends in '/chat' (singular, the action verb)
      2. Any POST CHAT endpoint not under '/admin/'
      3. First CHAT endpoint as-is
      4. First POST endpoint of any purpose
    """
    chats = profile.endpoints_for(EndpointPurpose.CHAT)
    def _score(e: EndpointSpec) -> tuple[int, int]:
        p = e.path.lower()
        is_post = e.method == HttpMethod.POST
        ends_chat = p.endswith("/chat") or p.endswith("/stream-chat")
        is_admin = "/admin/" in p
        is_thread = "/thread/" in p  # prefer the simpler non-thread route
        template_count = p.count("{")
        priority = (
            (0 if (is_post and ends_chat and not is_admin) else 1),
            (0 if not is_admin else 1),
            (0 if not is_thread else 1),
            template_count,
        )
        # Return a single tuple usable as sort key
        return priority  # type: ignore[return-value]
    if chats:
        return sorted(chats, key=_score)[0]
    for e in profile.endpoints:
        if e.method == HttpMethod.POST:
            return e
    return None


def _pick_health_endpoint(profile: AgentProfile) -> EndpointSpec | None:
    health = profile.endpoints_for(EndpointPurpose.HEALTH)
    if health:
        return health[0]
    for e in profile.endpoints:
        if e.method == HttpMethod.GET:
            return e
    return None


def _build_chat_payload(endpoint: EndpointSpec, prompt: str) -> dict[str, Any]:
    """Build the request body for a chat-style endpoint.

    Special-cases AnythingLLM (`/workspace/{slug}/chat` needs `mode: "chat"`),
    OpenAI-compat (`/chat/completions` wants a `messages` array), and
    Ollama-style (`/generate` wants a `model`). Otherwise falls back to the
    most common field name found in the OpenAPI schema.
    """
    schema = endpoint.request_schema or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    path = (endpoint.path or "").lower()

    if "/workspace/" in path and path.endswith(("/chat", "/stream-chat")):
        return {"message": prompt, "mode": "chat"}

    if "/chat/completions" in path or "messages" in props:
        return {"messages": [{"role": "user", "content": prompt}]}

    if "ollama" in path or path.endswith("/generate"):
        return {"model": "default", "prompt": prompt, "stream": False}

    for key in ("message", "messages", "prompt", "input", "query", "text", "content"):
        if key in props or not props:
            if key == "messages":
                return {"messages": [{"role": "user", "content": prompt}]}
            return {key: prompt}
    return {"message": prompt}


def _excerpt(text: str, limit: int = 160) -> str:
    text = (text or "").strip().replace("\r", " ").replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Preflight runner
# ---------------------------------------------------------------------------


@dataclass
class PreflightOptions:
    include_latency: bool = False
    warn_only: bool = False
    yes: bool = False
    interactive: bool | None = None  # None = auto-detect via stdin.isatty()
    chat_prompt: str = "Reply with exactly the single word: READY"


class Preflight:
    """Runs the rubric checks against an adapter and produces a result."""

    def __init__(
        self,
        profile: AgentProfile,
        adapter: Any,
        options: PreflightOptions | None = None,
    ) -> None:
        self.profile = profile
        self.adapter = adapter
        self.options = options or PreflightOptions()

    async def run(self) -> PreflightResult:
        result = PreflightResult(
            profile_name=self.profile.name,
            base_url=str(self.profile.base_url),
        )

        # Ordered check list. HARD-STOP aborts subsequent checks.
        steps: list[tuple[str, Callable[[], Any], bool]] = [
            ("tcp_reachable", self._check_tcp_reachable, True),
            ("http_responds", self._check_http_responds, True),
            ("auth_resolves", self._check_auth_resolves, True),
            ("auth_works", self._check_auth_works, False),
            ("chat_round_trip", self._check_chat_round_trip, True),
        ]
        if self.options.include_latency:
            steps.append(("baseline_latency", self._check_baseline_latency, False))
        steps.append(("endpoint_coverage", self._check_endpoint_coverage, False))

        for name, fn, hard_stop_capable in steps:
            try:
                check = await fn()
            except Exception as e:  # defensive — never let an exception escape preflight
                logger.exception("preflight check %s crashed", name)
                check = PreflightCheck(
                    name=name,
                    status="hard_stop" if hard_stop_capable else "warn",
                    evidence=f"check crashed: {e!s}",
                )
            result.checks.append(check)
            if check.status == "hard_stop":
                if self.options.warn_only:
                    check.status = "warn"  # downgrade
                else:
                    result.overall = "hard_stop"
                    return result

        if result.has_warn():
            result.overall = "warn"
        else:
            result.overall = "green"
        return result

    # ---- individual checks --------------------------------------------------

    async def _check_tcp_reachable(self) -> PreflightCheck:
        from urllib.parse import urlparse

        parsed = urlparse(str(self.profile.base_url))
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        start = time.perf_counter()
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=5.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            latency = (time.perf_counter() - start) * 1000
            return PreflightCheck(
                name="tcp_reachable",
                status="green",
                latency_ms=latency,
                evidence=f"{host}:{port}",
            )
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return PreflightCheck(
                name="tcp_reachable",
                status="hard_stop",
                latency_ms=latency,
                evidence=f"{host}:{port} unreachable: {e!s}",
            )

    async def _check_http_responds(self) -> PreflightCheck:
        ep = _pick_health_endpoint(self.profile)
        if ep is None:
            return PreflightCheck(
                name="http_responds",
                status="warn",
                evidence="no GET endpoint declared in profile",
            )
        resp = await self.adapter.invoke(ep, None)
        latency = float(getattr(resp, "latency_ms", 0.0))
        status = int(getattr(resp, "status_code", 0))
        if status == 0:
            err = getattr(resp, "error", "no response")
            return PreflightCheck(
                name="http_responds",
                status="hard_stop",
                latency_ms=latency,
                evidence=f"GET {ep.path} -> error: {err}",
            )
        if status >= 500:
            return PreflightCheck(
                name="http_responds",
                status="hard_stop",
                latency_ms=latency,
                evidence=f"GET {ep.path} -> {status}",
            )
        # 2xx/3xx/4xx-but-responding are all acceptable proof of life.
        return PreflightCheck(
            name="http_responds",
            status="green",
            latency_ms=latency,
            evidence=f"GET {ep.path} -> {status}",
        )

    async def _check_auth_resolves(self) -> PreflightCheck:
        auth = self.profile.auth
        if auth.scheme == AuthScheme.NONE:
            return PreflightCheck(
                name="auth_resolves",
                status="warn",
                evidence="auth scheme=none (no token required)",
            )
        if not auth.token_env_var:
            return PreflightCheck(
                name="auth_resolves",
                status="hard_stop",
                evidence=f"auth scheme={auth.scheme.value} but no token_env_var set",
            )
        value = os.environ.get(auth.token_env_var)
        if not _key_looks_real(value):
            return PreflightCheck(
                name="auth_resolves",
                status="hard_stop",
                evidence=(
                    f"env var {auth.token_env_var} missing or placeholder; "
                    "export a real token before scanning"
                ),
            )
        return PreflightCheck(
            name="auth_resolves",
            status="green",
            evidence=f"token from {auth.token_env_var} (len={len(value)})",
        )

    async def _check_auth_works(self) -> PreflightCheck:
        """WARN-only: some agents bypass auth on chat. Don't HARD-STOP here."""
        if self.profile.auth.scheme == AuthScheme.NONE:
            return PreflightCheck(
                name="auth_works",
                status="skipped",
                evidence="auth scheme=none",
            )
        # Prefer an AUTH endpoint; fall back to the health endpoint.
        ep = None
        auth_eps = self.profile.endpoints_for(EndpointPurpose.AUTH)
        if auth_eps:
            ep = auth_eps[0]
        else:
            ep = _pick_health_endpoint(self.profile)
        if ep is None:
            return PreflightCheck(
                name="auth_works",
                status="warn",
                evidence="no auth/health endpoint to probe",
            )
        resp = await self.adapter.invoke(ep, None)
        status = int(getattr(resp, "status_code", 0))
        latency = float(getattr(resp, "latency_ms", 0.0))
        if status in (401, 403):
            return PreflightCheck(
                name="auth_works",
                status="warn",
                latency_ms=latency,
                evidence=f"{ep.method.value} {ep.path} -> {status} (token may be wrong/expired)",
            )
        if 200 <= status < 400:
            return PreflightCheck(
                name="auth_works",
                status="green",
                latency_ms=latency,
                evidence=f"{ep.method.value} {ep.path} -> {status}",
            )
        return PreflightCheck(
            name="auth_works",
            status="warn",
            latency_ms=latency,
            evidence=f"{ep.method.value} {ep.path} -> {status}",
        )

    async def _check_chat_round_trip(self) -> PreflightCheck:
        ep = _pick_chat_endpoint(self.profile)
        if ep is None:
            return PreflightCheck(
                name="chat_round_trip",
                status="hard_stop",
                evidence="no CHAT endpoint declared in profile",
            )
        payload = _build_chat_payload(ep, self.options.chat_prompt)
        resp = await self.adapter.invoke(ep, payload)
        status = int(getattr(resp, "status_code", 0))
        latency = float(getattr(resp, "latency_ms", 0.0))
        if status == 0 or status >= 500:
            err = getattr(resp, "error", f"status={status}")
            return PreflightCheck(
                name="chat_round_trip",
                status="hard_stop",
                latency_ms=latency,
                evidence=f"POST {ep.path} failed: {err}",
            )
        if not (200 <= status < 400):
            return PreflightCheck(
                name="chat_round_trip",
                status="hard_stop",
                latency_ms=latency,
                evidence=f"POST {ep.path} -> {status}",
            )
        # Extract a human-readable excerpt for visible proof.
        body_text = _extract_text(resp)
        excerpt = _excerpt(body_text)
        return PreflightCheck(
            name="chat_round_trip",
            status="green",
            latency_ms=latency,
            evidence=f'"{excerpt}"' if excerpt else f"POST {ep.path} -> {status}",
            detail={"excerpt": excerpt, "status_code": status},
        )

    async def _check_baseline_latency(self) -> PreflightCheck:
        ep = _pick_chat_endpoint(self.profile)
        if ep is None:
            return PreflightCheck(
                name="baseline_latency",
                status="skipped",
                evidence="no chat endpoint",
            )
        latencies: list[float] = []
        for _ in range(2):
            payload = _build_chat_payload(ep, "ping")
            resp = await self.adapter.invoke(ep, payload)
            latencies.append(float(getattr(resp, "latency_ms", 0.0)))
        if not latencies:
            return PreflightCheck(name="baseline_latency", status="warn", evidence="no samples")
        mean = statistics.fmean(latencies)
        p95 = max(latencies)  # only 2 samples — max approximates p95
        return PreflightCheck(
            name="baseline_latency",
            status="green",
            latency_ms=mean,
            evidence=f"mean={mean:.0f}ms p95={p95:.0f}ms (n={len(latencies)})",
            detail={"latencies_ms": [round(x, 2) for x in latencies], "mean_ms": mean, "p95_ms": p95},
        )

    async def _check_endpoint_coverage(self) -> PreflightCheck:
        total = len(self.profile.endpoints)
        if total == 0:
            return PreflightCheck(
                name="endpoint_coverage",
                status="warn",
                evidence="profile has zero endpoints",
            )
        reachable = 0
        for ep in self.profile.endpoints:
            if ep.method != HttpMethod.GET:
                continue
            try:
                resp = await self.adapter.invoke(ep, None)
                status = int(getattr(resp, "status_code", 0))
                if 200 <= status < 500 and status != 0:
                    reachable += 1
            except Exception:
                continue
        get_count = sum(1 for e in self.profile.endpoints if e.method == HttpMethod.GET)
        return PreflightCheck(
            name="endpoint_coverage",
            status="green",
            evidence=f"{reachable}/{get_count} GET endpoints reachable ({total} total)",
            detail={"reachable_get": reachable, "total_get": get_count, "total": total},
        )


def _extract_text(resp: Any) -> str:
    """Pull a human-readable string out of an AdapterResponse."""
    data = getattr(resp, "data", None)
    if isinstance(data, dict):
        # Common envelope shapes
        for key in ("textResponse", "response", "answer", "output", "message", "content", "text", "reply"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                return v
        # OpenAI-compat
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message") or {}
                if isinstance(msg, dict):
                    c = msg.get("content")
                    if isinstance(c, str):
                        return c
                txt = first.get("text")
                if isinstance(txt, str):
                    return txt
    raw = getattr(resp, "raw_text", "") or ""
    return raw


# ---------------------------------------------------------------------------
# Rich-console rendering
# ---------------------------------------------------------------------------


def render_console(result: PreflightResult, console: Any) -> None:
    """Render a PreflightResult to a Rich Console as a table + banner."""
    try:
        from rich.table import Table
    except Exception:
        console.print(f"Preflight: {result.profile_name} -> {result.overall.upper()}")
        for c in result.checks:
            console.print(f"  [{c.icon}] {c.name}  {c.latency_ms:.0f}ms  {c.evidence}")
        return

    table = Table(
        title=f"Preflight: {result.profile_name}",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Latency", justify="right")
    table.add_column("Evidence")

    icon_color = {
        "green": "[green]OK[/green]",
        "warn": "[yellow]WARN[/yellow]",
        "hard_stop": "[red]FAIL[/red]",
        "skipped": "[dim]skip[/dim]",
    }
    for c in result.checks:
        table.add_row(
            c.name,
            icon_color[c.status],
            f"{c.latency_ms:.0f} ms" if c.latency_ms else "--",
            c.evidence,
        )
    console.print(table)

    if result.overall == "green":
        console.print("\n[bold green]===== READY TO SCAN =====[/bold green]\n")
    elif result.overall == "warn":
        console.print("\n[bold yellow]===== PREFLIGHT WARNINGS — review above =====[/bold yellow]\n")
    else:
        console.print("\n[bold red]===== PREFLIGHT FAILED =====[/bold red]\n")


# ---------------------------------------------------------------------------
# Interactive consent
# ---------------------------------------------------------------------------


def confirm_proceed_on_warn(
    result: PreflightResult,
    *,
    yes: bool,
    interactive: bool | None = None,
    prompt_fn: Callable[[str], str] | None = None,
) -> bool:
    """Return True if the operator agrees to proceed despite warnings.

    Fail-closed when stdin is not a TTY and ``yes`` is False.
    """
    if yes:
        return True
    is_tty = interactive if interactive is not None else sys.stdin.isatty()
    if not is_tty:
        return False
    fn = prompt_fn or input
    try:
        answer = fn("Proceed anyway? [y/N]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")
