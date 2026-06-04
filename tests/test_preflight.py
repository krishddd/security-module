"""Unit tests for core.preflight — no live network. Mocks adapter.invoke."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable
from unittest.mock import patch

import pytest

from core.preflight import (
    Preflight,
    PreflightOptions,
    confirm_proceed_on_warn,
    render_console,
)
from models.agent_profile import (
    AgentProfile,
    AuthConfig,
    AuthScheme,
    EndpointPurpose,
    EndpointSpec,
    HttpMethod,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@dataclass
class FakeResp:
    status_code: int = 200
    data: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 10.0
    ttfb_ms: float = 10.0
    headers: dict[str, str] = field(default_factory=dict)
    raw_text: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


class FakeAdapter:
    """Records calls; returns canned responses keyed by path."""

    def __init__(self, responses: dict[str, FakeResp] | None = None, default: FakeResp | None = None) -> None:
        self.responses = responses or {}
        self.default = default or FakeResp(200, {"ok": True})
        self.calls: list[tuple[str, str, Any]] = []

    async def invoke(self, endpoint: EndpointSpec, payload: Any = None) -> FakeResp:
        self.calls.append((endpoint.method.value, endpoint.path, payload))
        return self.responses.get(endpoint.path, self.default)

    async def close(self) -> None:
        pass


def make_profile(
    *,
    auth_scheme: AuthScheme = AuthScheme.NONE,
    token_env_var: str | None = None,
    base_url: str = "http://example.test:9100",
) -> AgentProfile:
    return AgentProfile(
        name="test_agent",
        base_url=base_url,  # type: ignore[arg-type]
        auth=AuthConfig(scheme=auth_scheme, token_env_var=token_env_var),
        endpoints=[
            EndpointSpec(path="/health", method=HttpMethod.GET, purpose=EndpointPurpose.HEALTH),
            EndpointSpec(path="/chat", method=HttpMethod.POST, purpose=EndpointPurpose.CHAT),
        ],
    )


# Stub out the TCP probe so we don't actually open sockets.
@pytest.fixture(autouse=True)
def _stub_tcp(monkeypatch):
    async def _ok(*args, **kwargs):
        class W:
            def close(self): pass
            async def wait_closed(self): pass
        return (object(), W())
    monkeypatch.setattr("asyncio.open_connection", _ok)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_green_path(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "real-token-1234567890")
    profile = make_profile(auth_scheme=AuthScheme.BEARER, token_env_var="MY_TOKEN")
    adapter = FakeAdapter(default=FakeResp(200, {"textResponse": "READY"}))
    result = await Preflight(profile, adapter).run()
    assert result.overall == "green", [(c.name, c.status, c.evidence) for c in result.checks]
    names = {c.name for c in result.checks}
    assert "tcp_reachable" in names
    assert "http_responds" in names
    assert "chat_round_trip" in names
    chat = next(c for c in result.checks if c.name == "chat_round_trip")
    assert "READY" in chat.evidence


@pytest.mark.asyncio
async def test_hard_stop_tcp_unreachable(monkeypatch):
    async def _fail(*a, **kw):
        raise OSError("Connection refused")
    monkeypatch.setattr("asyncio.open_connection", _fail)
    profile = make_profile()
    adapter = FakeAdapter()
    result = await Preflight(profile, adapter).run()
    assert result.overall == "hard_stop"
    # Subsequent checks must NOT have run.
    assert len(result.checks) == 1
    assert result.checks[0].name == "tcp_reachable"
    assert len(adapter.calls) == 0


@pytest.mark.asyncio
async def test_warn_auth_bad_token(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "real-token-1234567890")
    profile = make_profile(auth_scheme=AuthScheme.BEARER, token_env_var="MY_TOKEN")
    adapter = FakeAdapter(
        responses={
            "/health": FakeResp(401, {"error": "unauthorized"}),
            "/chat": FakeResp(200, {"textResponse": "OK"}),
        }
    )
    result = await Preflight(profile, adapter).run()
    # auth_works is WARN, not HARD-STOP; auth_resolves passes since token is real.
    assert result.overall == "warn"
    aw = next(c for c in result.checks if c.name == "auth_works")
    assert aw.status == "warn"


@pytest.mark.asyncio
async def test_auth_resolves_hard_stops_on_missing_env(monkeypatch):
    monkeypatch.delenv("MY_TOKEN", raising=False)
    profile = make_profile(auth_scheme=AuthScheme.BEARER, token_env_var="MY_TOKEN")
    adapter = FakeAdapter()
    result = await Preflight(profile, adapter).run()
    assert result.overall == "hard_stop"
    ar = next(c for c in result.checks if c.name == "auth_resolves")
    assert ar.status == "hard_stop"


@pytest.mark.asyncio
async def test_auth_resolves_placeholder_rejected(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "xxxxxxxxxxxxxxx")
    profile = make_profile(auth_scheme=AuthScheme.BEARER, token_env_var="MY_TOKEN")
    adapter = FakeAdapter()
    result = await Preflight(profile, adapter).run()
    assert result.overall == "hard_stop"


@pytest.mark.asyncio
async def test_chat_round_trip_hard_stop_on_5xx():
    profile = make_profile()
    adapter = FakeAdapter(
        responses={
            "/health": FakeResp(200),
            "/chat": FakeResp(500, {"error": "boom"}),
        }
    )
    result = await Preflight(profile, adapter).run()
    assert result.overall == "hard_stop"
    chat = next(c for c in result.checks if c.name == "chat_round_trip")
    assert chat.status == "hard_stop"


@pytest.mark.asyncio
async def test_baseline_latency_opt_in_runs_two_calls():
    profile = make_profile()
    adapter = FakeAdapter(default=FakeResp(200, {"textResponse": "ok"}))

    # Without flag — baseline_latency check absent
    r1 = await Preflight(profile, adapter).run()
    assert "baseline_latency" not in {c.name for c in r1.checks}

    adapter2 = FakeAdapter(default=FakeResp(200, {"textResponse": "ok"}))
    r2 = await Preflight(profile, adapter2, PreflightOptions(include_latency=True)).run()
    bl = next(c for c in r2.checks if c.name == "baseline_latency")
    assert bl.status == "green"
    # Should have exactly 2 chat invocations for latency, plus chat_round_trip
    chat_calls = [c for c in adapter2.calls if c[1] == "/chat"]
    assert len(chat_calls) == 3  # 1 round_trip + 2 latency


@pytest.mark.asyncio
async def test_warn_only_downgrades_hard_stops(monkeypatch):
    # auth_resolves HARD-STOP gets downgraded to WARN
    monkeypatch.delenv("MY_TOKEN", raising=False)
    profile = make_profile(auth_scheme=AuthScheme.BEARER, token_env_var="MY_TOKEN")
    adapter = FakeAdapter(default=FakeResp(200, {"textResponse": "OK"}))
    result = await Preflight(profile, adapter, PreflightOptions(warn_only=True)).run()
    assert result.overall == "warn"


def test_confirm_proceed_yes_bypass():
    from core.preflight import PreflightResult
    res = PreflightResult(profile_name="x", base_url="http://x")
    assert confirm_proceed_on_warn(res, yes=True) is True


def test_confirm_proceed_non_tty_fails_closed():
    from core.preflight import PreflightResult
    res = PreflightResult(profile_name="x", base_url="http://x")
    assert confirm_proceed_on_warn(res, yes=False, interactive=False) is False


def test_confirm_proceed_tty_prompts_default_no():
    from core.preflight import PreflightResult
    res = PreflightResult(profile_name="x", base_url="http://x")
    assert confirm_proceed_on_warn(res, yes=False, interactive=True, prompt_fn=lambda q: "") is False
    assert confirm_proceed_on_warn(res, yes=False, interactive=True, prompt_fn=lambda q: "n") is False
    assert confirm_proceed_on_warn(res, yes=False, interactive=True, prompt_fn=lambda q: "y") is True
    assert confirm_proceed_on_warn(res, yes=False, interactive=True, prompt_fn=lambda q: "yes") is True


def test_ssrf_guard_blocks_loopback_without_flag():
    from core.ssrf_guard import assert_url_safe, SSRFBlockedError
    with pytest.raises(SSRFBlockedError):
        assert_url_safe("http://127.0.0.1:9100/", allow_internal=False)
    # with flag — no exception
    assert_url_safe("http://127.0.0.1:9100/", allow_internal=True)


@pytest.mark.asyncio
async def test_endpoint_coverage_informational():
    profile = make_profile()
    adapter = FakeAdapter(default=FakeResp(200, {"textResponse": "OK"}))
    result = await Preflight(profile, adapter).run()
    cov = next(c for c in result.checks if c.name == "endpoint_coverage")
    # Never blocks; status is green/warn but not hard_stop
    assert cov.status in ("green", "warn")
    assert result.overall != "hard_stop"


@pytest.mark.asyncio
async def test_render_console_does_not_crash():
    """Smoke test for the Rich rendering path."""
    from rich.console import Console
    profile = make_profile()
    adapter = FakeAdapter(default=FakeResp(200, {"textResponse": "READY"}))
    result = await Preflight(profile, adapter).run()
    console = Console(record=True, legacy_windows=True)
    render_console(result, console)
    output = console.export_text()
    assert "READY TO SCAN" in output or "PREFLIGHT" in output
