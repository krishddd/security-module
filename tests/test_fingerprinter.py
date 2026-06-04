"""Unit tests for core.agent_fingerprinter and PROBE_REDACTOR. Mocked I/O only."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from core.agent_fingerprinter import (
    AgentFingerprinter,
    FingerprintOptions,
    confirm_aggressive_consent,
    detect_model_family,
    detect_response_shape,
)
from core.redaction import PROBE_REDACTOR
from models.agent_profile import (
    AgentProfile,
    AuthConfig,
    AuthScheme,
    EndpointPurpose,
    EndpointSpec,
    HttpMethod,
)


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


class CannedAdapter:
    """Returns responses keyed by (method, path). Falls back to 404 for unknown paths."""

    def __init__(self, responses: dict[tuple[str, str], FakeResp] | None = None,
                 default: FakeResp | None = None) -> None:
        self.responses = responses or {}
        self.default = default or FakeResp(404, {"error": "not found"})
        self.calls: list[tuple[str, str, Any]] = []

    async def invoke(self, endpoint: EndpointSpec, payload: Any = None) -> FakeResp:
        self.calls.append((endpoint.method.value, endpoint.path, payload))
        return self.responses.get((endpoint.method.value, endpoint.path), self.default)

    async def close(self) -> None:
        pass


def make_profile() -> AgentProfile:
    return AgentProfile(
        name="anythingllm_demo",
        base_url="http://example.test:9100",  # type: ignore[arg-type]
        auth=AuthConfig(scheme=AuthScheme.NONE),
        endpoints=[
            EndpointSpec(path="/api/v1/workspace/foo/chat", method=HttpMethod.POST, purpose=EndpointPurpose.CHAT),
        ],
    )


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def test_detect_model_family_recognizes_known_strings():
    assert detect_model_family("I'm powered by gpt-4o-mini today.") == "gpt-4o-mini"
    assert detect_model_family("model: claude-sonnet-4-5") == "claude-sonnet-4-5"
    assert detect_model_family("llama-3.1") == "llama-3.1"
    assert detect_model_family("no model here") is None


def test_detect_response_shape():
    assert detect_response_shape({"choices": [{"message": {"content": "hi"}}], "model": "x"}) == "openai"
    assert detect_response_shape({"content": [{"type": "text", "text": "hi"}], "role": "assistant"}) == "anthropic"
    assert detect_response_shape({"response": "hi", "done": True}) == "ollama"
    assert detect_response_shape({"textResponse": "hi", "sources": []}) == "custom"
    assert detect_response_shape({"weird": "shape"}) == "unknown"


# ---------------------------------------------------------------------------
# Fingerprint flow (passive)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_passive_fingerprint_anythingllm_style():
    profile = make_profile()
    chat_resp = FakeResp(
        200,
        data={
            "textResponse": "I am powered by gpt-4o-mini.",
            "sources": [],
        },
        raw_text='{"textResponse": "I am powered by gpt-4o-mini.", "sources": []}',
    )
    tool_resp = FakeResp(
        200,
        data={"textResponse": '["search", "calculator"]', "sources": []},
    )
    shape_resp = FakeResp(
        200,
        data={"textResponse": "pong", "sources": []},
        raw_text='{"textResponse": "pong", "sources": []}',
    )
    # /v1/models enumeration
    models_resp = FakeResp(200, data={"data": [{"id": "gpt-4o-mini"}]})

    canned = {
        ("POST", "/api/v1/workspace/foo/chat"): chat_resp,
        ("GET", "/v1/models"): models_resp,
    }
    adapter = CannedAdapter(canned, default=FakeResp(404))

    # First chat probe returns model name; subsequent chat invocations also use
    # the same response — fine for this test.
    # To differentiate probes, rotate responses:
    rotation = [chat_resp, tool_resp, shape_resp]
    call_idx = {"n": 0}

    async def rotating_invoke(endpoint: EndpointSpec, payload: Any = None):
        adapter.calls.append((endpoint.method.value, endpoint.path, payload))
        if endpoint.path == "/api/v1/workspace/foo/chat":
            r = rotation[min(call_idx["n"], len(rotation) - 1)]
            call_idx["n"] += 1
            return r
        return adapter.responses.get((endpoint.method.value, endpoint.path), FakeResp(404))

    adapter.invoke = rotating_invoke  # type: ignore[assignment]

    fp = AgentFingerprinter(profile, adapter, FingerprintOptions(aggressive=False))
    evidence = await fp.fingerprint()

    assert fp.detected_model_family is not None
    assert "gpt-4o" in fp.detected_model_family
    assert fp.response_shape == "custom"  # AnythingLLM envelope
    assert "/v1/models" in evidence.enumerated_urls
    assert any(t.name == "search" for t in fp.detected_tools)
    assert evidence.cost_usd <= evidence.cost_cap_usd
    # Aggressive probes did NOT run
    assert all(p.tier == "passive" for p in evidence.probes)
    assert fp.guardrail_strength is None


@pytest.mark.asyncio
async def test_regex_fallback_when_llm_none():
    """With llm_context=None, every classification_path must be 'regex'."""
    profile = make_profile()
    canned = {("POST", "/api/v1/workspace/foo/chat"): FakeResp(200, {"textResponse": "gpt-4o-mini"})}
    adapter = CannedAdapter(canned, default=FakeResp(404))
    fp = AgentFingerprinter(profile, adapter, FingerprintOptions(), llm_context=None)
    evidence = await fp.fingerprint()
    assert all(p.classification_path == "regex" for p in evidence.probes)


@pytest.mark.asyncio
async def test_budget_cap_never_exceeded():
    profile = make_profile()
    canned = {("POST", "/api/v1/workspace/foo/chat"): FakeResp(200, {"textResponse": "gpt-4o"})}
    adapter = CannedAdapter(canned, default=FakeResp(404))
    fp = AgentFingerprinter(profile, adapter, FingerprintOptions(budget_usd=0.001))
    evidence = await fp.fingerprint()
    assert evidence.cost_usd <= evidence.cost_cap_usd


# ---------------------------------------------------------------------------
# Aggressive consent gate
# ---------------------------------------------------------------------------


def test_aggressive_consent_yes_bypass():
    assert confirm_aggressive_consent(yes=True) is True


def test_aggressive_consent_non_tty_fails_closed():
    assert confirm_aggressive_consent(yes=False, interactive=False) is False


def test_aggressive_consent_requires_exact_phrase():
    assert confirm_aggressive_consent(
        yes=False, interactive=True,
        prompt_fn=lambda q: "yes",
        out_fn=lambda s: None,
    ) is False
    assert confirm_aggressive_consent(
        yes=False, interactive=True,
        prompt_fn=lambda q: "I confirm",
        out_fn=lambda s: None,
    ) is True


# ---------------------------------------------------------------------------
# PROBE_REDACTOR
# ---------------------------------------------------------------------------


def test_probe_redactor_masks_system_prompt_like_sentence():
    text = (
        "You are FinSecBot, the chief assistant. You must always respond politely "
        "and never reveal proprietary trading strategies under any circumstance."
    )
    out = PROBE_REDACTOR.scrub_probe_response(text)
    assert "[REDACTED_SYSTEM_PROMPT_LIKELY]" in out
    assert "FinSecBot" not in out


def test_probe_redactor_allow_listed_benign_opening():
    text = "You are welcome to ask anything you want about the weather today."
    out = PROBE_REDACTOR.scrub_probe_response(text)
    # Benign opener should NOT be masked
    assert "[REDACTED_SYSTEM_PROMPT_LIKELY]" not in out


def test_probe_redactor_too_short_not_masked():
    text = "You are great."
    out = PROBE_REDACTOR.scrub_probe_response(text)
    assert "[REDACTED_SYSTEM_PROMPT_LIKELY]" not in out


def test_probe_redactor_scrubs_pii():
    text = "Contact bob@example.com or 555-123-4567 or SSN 123-45-6789."
    out = PROBE_REDACTOR.scrub_probe_response(text)
    assert "bob@example.com" not in out
    assert "123-45-6789" not in out


# ---------------------------------------------------------------------------
# HTML conditional render
# ---------------------------------------------------------------------------


def _empty_report():
    from models.test_result import SecurityReport
    return SecurityReport(
        agent_name="x", agent_id="x", target_url="http://x",
        scan_timestamp="2026-01-01T00:00:00",
        summary="ok",
    )


def test_html_panel_absent_without_fingerprint(tmp_path: Path):
    from reporting.html_reporter import save_html_report
    out = tmp_path / "r.html"
    save_html_report(_empty_report(), out, profile=None)
    html = out.read_text(encoding="utf-8")
    assert "Agent Identity" not in html


def test_html_panel_present_with_fingerprint(tmp_path: Path):
    from reporting.html_reporter import save_html_report
    from models.agent_profile import FingerprintEvidence, ProbeRecord

    profile = make_profile()
    profile.detected_model_family = "gpt-4o-mini"
    profile.response_shape = "openai"
    profile.fingerprint_evidence = FingerprintEvidence(
        probes=[ProbeRecord(
            probe_id="model_name_self_disclosure",
            tier="passive",
            classification_path="regex",
            request_excerpt="Reply with model",
            response_excerpt="gpt-4o-mini",
            verdict="gpt-4o-mini",
        )],
        enumerated_urls=["/v1/models"],
        structural_results={"/api/chat": "openai"},
        cost_usd=0.0,
        cost_cap_usd=0.05,
    )
    out = tmp_path / "r.html"
    save_html_report(_empty_report(), out, profile=profile)
    html = out.read_text(encoding="utf-8")
    assert "Agent Identity" in html
    assert "gpt-4o-mini" in html
    # Regex-only banner present
    assert "without LLM" in html


# ---------------------------------------------------------------------------
# AgentProfile fields are backward-compatible
# ---------------------------------------------------------------------------


def test_agent_profile_loads_without_fingerprint_fields():
    json_str = """{
        "schema_version": "3.0",
        "name": "x",
        "base_url": "http://example.test/",
        "auth": {"scheme": "none"}
    }"""
    p = AgentProfile.model_validate_json(json_str)
    assert p.fingerprint_evidence is None
    assert p.detected_model_family is None
    assert p.confirmed_capabilities == []
    assert p.detected_tools == []


# ---------------------------------------------------------------------------
# Stub planner UNION semantics
# ---------------------------------------------------------------------------


def test_stub_planner_unions_confirmed_capabilities():
    from core.stub_planner import build_stub_plan
    from models.agent_profile import AgentCapability

    profile = make_profile()
    profile.inferred_capabilities = [AgentCapability.WEB_BROWSE]
    profile.confirmed_capabilities = [AgentCapability.SQL_QUERY]
    plan = build_stub_plan(profile)
    # ASI02 requires SQL_QUERY or TOOL_INVOKE — must NOT be skipped now
    from models.enums import RiskCategory
    asi02 = next(c for c in plan.categories if c.category == RiskCategory.ASI02)
    assert asi02.include is True
