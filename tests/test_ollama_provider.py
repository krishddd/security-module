"""Ollama (local / air-gapped) provider — mirrors the LLMResponse contract.

All tests stub the httpx client; no live Ollama server is contacted.
"""

from __future__ import annotations

import pytest

from llm.client import LLMUnavailableError
from llm.ollama_client import OllamaClient


class _FakeResp:
    def __init__(self, data: dict) -> None:
        self._data = data

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._data


class _FakeHttpClient:
    """Stands in for the httpx.Client OllamaClient holds."""

    def __init__(self, *, chat: dict | None = None, tags: dict | None = None, captured: dict) -> None:
        self._chat = chat or {}
        self._tags = tags or {"models": []}
        self._captured = captured

    def post(self, path: str, json: dict | None = None):
        self._captured["path"] = path
        self._captured["payload"] = json
        return _FakeResp(self._chat)

    def get(self, path: str):
        self._captured["get_path"] = path
        return _FakeResp(self._tags)


def _client_with(chat: dict | None = None, tags: dict | None = None) -> tuple[OllamaClient, dict]:
    # Construction makes no network call (httpx.Client is lazy); swap in the fake.
    client = OllamaClient()
    captured: dict = {}
    client._client = _FakeHttpClient(chat=chat, tags=tags, captured=captured)
    return client, captured


def test_simple_text_and_usage() -> None:
    client, cap = _client_with(chat={
        "model": "llama3.1",
        "message": {"role": "assistant", "content": "hello world", "tool_calls": []},
        "prompt_eval_count": 100,
        "eval_count": 50,
        "done": True,
        "done_reason": "stop",
    })
    resp = client.message(model="llama3.1", system="static", user="hi")
    assert resp.text == "hello world"
    assert resp.tool_uses == []
    assert resp.usage.input_tokens == 100
    assert resp.usage.output_tokens == 50
    assert resp.stop_reason == "stop"
    # Wire shape: non-streaming POST /api/chat with system+user and options.
    assert cap["path"] == "/api/chat"
    assert cap["payload"]["stream"] is False
    assert cap["payload"]["options"]["temperature"] == 0.2
    assert cap["payload"]["options"]["num_predict"] == 2048
    assert [m["role"] for m in cap["payload"]["messages"]] == ["system", "user"]


def test_tool_use_mapped_to_anthropic_shape() -> None:
    client, cap = _client_with(chat={
        "model": "llama3.1",
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "submit_plan",
                              "arguments": {"categories": [{"category": "ASI01", "include": True}]}}}
            ],
        },
        "done": True,
    })
    tools = [{"name": "submit_plan", "description": "...", "input_schema": {"type": "object"}}]
    resp = client.message(model="llama3.1", system="static", user="plan it", tools=tools)
    assert len(resp.tool_uses) == 1
    assert resp.tool_uses[0]["name"] == "submit_plan"
    assert resp.tool_uses[0]["input"]["categories"][0]["category"] == "ASI01"
    # Tools serialized in the OpenAI-compatible shape Ollama accepts.
    assert cap["payload"]["tools"][0]["type"] == "function"
    assert cap["payload"]["tools"][0]["function"]["name"] == "submit_plan"


def test_tool_arguments_as_json_string_are_parsed() -> None:
    """Some Ollama builds return arguments as a JSON string — tolerate it."""
    client, _ = _client_with(chat={
        "message": {"content": "", "tool_calls": [
            {"function": {"name": "f", "arguments": '{"x": 1}'}}
        ]},
        "done": True,
    })
    resp = client.message(model="llama3.1", system="s", user="u",
                          tools=[{"name": "f", "input_schema": {"type": "object"}}])
    assert resp.tool_uses[0]["input"] == {"x": 1}


def test_profile_leak_check_fires() -> None:
    client, _ = _client_with(chat={"message": {"content": "ok"}, "done": True})
    with pytest.raises(AssertionError, match="prompt-cache contract"):
        client.message(model="llama3.1", system='"base_url": "http://x"', user="hi")


def test_validate_models_missing_raises() -> None:
    client, _ = _client_with(tags={"models": [{"name": "mistral:latest"}]})
    # Default OLLAMA_MODEL_* is llama3.1, which isn't installed here.
    with pytest.raises(LLMUnavailableError, match="not pulled locally"):
        client._validate_models()


def test_validate_models_present_passes() -> None:
    client, _ = _client_with(tags={"models": [{"name": "llama3.1:latest"}]})
    client._validate_models()  # bare-name match against "llama3.1" — no raise
    assert client._validated is True


def test_unreachable_server_raises_clear_error() -> None:
    import httpx
    client, _ = _client_with()

    def _boom(path):
        raise httpx.ConnectError("connection refused")

    client._client.get = _boom  # type: ignore[assignment]
    with pytest.raises(LLMUnavailableError, match="could not reach Ollama"):
        client._validate_models()


# ---- LLMContext wiring ----------------------------------------------------


def test_context_explicit_ollama_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """provider='ollama' selects the local client with NO API key required."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    from llm.context import LLMContext
    from config.settings import OLLAMA_MODEL_PLANNER

    ctx = LLMContext.enable(provider="ollama")
    assert ctx.provider == "ollama"
    assert isinstance(ctx.client, OllamaClient)
    assert ctx.planner.model == OLLAMA_MODEL_PLANNER
