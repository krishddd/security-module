"""OpenAI provider — mirrors the Anthropic LLMResponse contract.

All tests stub the openai SDK; no live API calls.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest


def _mock_openai(monkeypatch: pytest.MonkeyPatch, *, captured: dict, response_overrides: dict | None = None) -> None:
    """Install a fake openai module in sys.modules."""
    import sys

    overrides = response_overrides or {}

    class FakeFn:
        def __init__(self, name: str, arguments: str) -> None:
            self.name = name
            self.arguments = arguments

    class FakeToolCall:
        def __init__(self, id_: str, name: str, args: dict) -> None:
            self.id = id_
            self.function = FakeFn(name, json.dumps(args))

    class FakeMessage:
        def __init__(self, content: str, tool_calls: list | None) -> None:
            self.content = content
            self.tool_calls = tool_calls or []

    class FakeChoice:
        def __init__(self, message: FakeMessage, finish_reason: str) -> None:
            self.message = message
            self.finish_reason = finish_reason

    class FakeUsage:
        def __init__(self) -> None:
            self.prompt_tokens = 100
            self.completion_tokens = 50
            self.prompt_tokens_details = SimpleNamespace(cached_tokens=80)

    class FakeResp:
        def __init__(self, **kwargs) -> None:
            self.model = kwargs.get("model", "gpt-4o")
            self.usage = FakeUsage()
            content = overrides.get("content", "ok")
            tools = overrides.get("tool_calls", [])
            tool_call_objs = [FakeToolCall(t["id"], t["name"], t["args"]) for t in tools]
            finish = overrides.get("finish_reason", "tool_calls" if tools else "stop")
            self.choices = [FakeChoice(FakeMessage(content, tool_call_objs), finish)]

    class FakeChat:
        class FakeCompletions:
            def create(self, **kwargs):
                captured["kwargs"] = kwargs
                return FakeResp(**kwargs)
        completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, api_key: str) -> None:
            self.api_key = api_key
            self.chat = FakeChat()
            self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[
                SimpleNamespace(id="gpt-4o"),
                SimpleNamespace(id="gpt-4o-mini"),
            ]))

    fake_module = SimpleNamespace(OpenAI=FakeOpenAI)
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-test-1234567890abcdef")


def test_no_api_key_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_openai(monkeypatch, captured={})
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    import importlib, llm.openai_client
    importlib.reload(llm.openai_client)
    from llm.client import LLMUnavailableError
    with pytest.raises(LLMUnavailableError, match="OPENAI_API_KEY"):
        llm.openai_client.OpenAIClient()


def test_simple_text_response(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _mock_openai(monkeypatch, captured=captured, response_overrides={"content": "hello world"})
    import importlib, llm.openai_client
    importlib.reload(llm.openai_client)

    client = llm.openai_client.OpenAIClient()
    resp = client.message(model="gpt-4o", system="static", user="hi")
    assert resp.text == "hello world"
    assert resp.tool_uses == []
    assert resp.usage.input_tokens == 100
    assert resp.usage.output_tokens == 50
    assert resp.usage.cache_read_input_tokens == 80


def test_tool_use_translated_to_anthropic_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _mock_openai(
        monkeypatch, captured=captured,
        response_overrides={
            "content": "",
            "tool_calls": [{"id": "call_1", "name": "submit_plan",
                            "args": {"categories": [{"category": "ASI01", "include": True}]}}],
        },
    )
    import importlib, llm.openai_client
    importlib.reload(llm.openai_client)

    client = llm.openai_client.OpenAIClient()
    tools = [{"name": "submit_plan", "description": "...", "input_schema": {"type": "object"}}]
    resp = client.message(model="gpt-4o", system="static", user="plan it", tools=tools)
    assert len(resp.tool_uses) == 1
    assert resp.tool_uses[0]["name"] == "submit_plan"
    assert resp.tool_uses[0]["input"]["categories"][0]["category"] == "ASI01"


def test_tool_spec_translation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anthropic-style {name, description, input_schema} -> OpenAI {type, function}."""
    captured: dict = {}
    _mock_openai(monkeypatch, captured=captured)
    import importlib, llm.openai_client
    importlib.reload(llm.openai_client)

    client = llm.openai_client.OpenAIClient()
    tools = [{"name": "do_x", "description": "X-er", "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}]
    client.message(model="gpt-4o", system="s", user="u", tools=tools)
    sent_tools = captured["kwargs"]["tools"]
    assert sent_tools[0]["type"] == "function"
    assert sent_tools[0]["function"]["name"] == "do_x"
    assert sent_tools[0]["function"]["parameters"]["properties"]["q"]["type"] == "string"
    # Single tool -> tool_choice forces it.
    assert captured["kwargs"]["tool_choice"]["function"]["name"] == "do_x"


def test_profile_leak_check_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_openai(monkeypatch, captured={})
    import importlib, llm.openai_client
    importlib.reload(llm.openai_client)

    client = llm.openai_client.OpenAIClient()
    with pytest.raises(AssertionError, match="prompt-cache contract"):
        client.message(model="gpt-4o", system='"base_url": "http://x"', user="hi")


# ---- LLMContext provider selection ---------------------------------------


def test_context_picks_anthropic_when_both_keys_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_openai(monkeypatch, captured={})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real-key-1234567890abcdef")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-real-key-1234567890abcdef")

    # Stub the anthropic side too so ClaudeClient init succeeds.
    import sys
    class FakeMsgs:
        def create(self, **k): ...
    class FakeAnt:
        def __init__(self, api_key: str): self.messages = FakeMsgs(); self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[]))
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=FakeAnt))

    import importlib, config.settings, llm.client, llm.openai_client, llm.context
    importlib.reload(config.settings); importlib.reload(llm.client)
    importlib.reload(llm.openai_client); importlib.reload(llm.context)

    ctx = llm.context.LLMContext.enable()
    assert ctx.provider == "anthropic"


def test_context_falls_back_to_openai_when_only_openai_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_openai(monkeypatch, captured={})
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-real-key-1234567890abcdef")

    import importlib, config.settings, llm.client, llm.openai_client, llm.context
    importlib.reload(config.settings); importlib.reload(llm.client)
    importlib.reload(llm.openai_client); importlib.reload(llm.context)

    ctx = llm.context.LLMContext.enable()
    assert ctx.provider == "openai"


def test_context_rejects_placeholder_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_openai(monkeypatch, captured={})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "****************************")  # masked placeholder
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-real-key-1234567890abcdef")

    import importlib, config.settings, llm.client, llm.openai_client, llm.context
    importlib.reload(config.settings); importlib.reload(llm.client)
    importlib.reload(llm.openai_client); importlib.reload(llm.context)

    ctx = llm.context.LLMContext.enable()
    # The asterisk placeholder is rejected, so OpenAI is picked.
    assert ctx.provider == "openai"


def test_context_explicit_provider_override(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_openai(monkeypatch, captured={})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-real-key-1234567890abcdef")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-real-key-1234567890abcdef")

    import sys
    class FakeMsgs:
        def create(self, **k): ...
    class FakeAnt:
        def __init__(self, api_key: str): self.messages = FakeMsgs(); self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[]))
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=FakeAnt))

    import importlib, config.settings, llm.client, llm.openai_client, llm.context
    importlib.reload(config.settings); importlib.reload(llm.client)
    importlib.reload(llm.openai_client); importlib.reload(llm.context)

    ctx = llm.context.LLMContext.enable(provider="openai")
    assert ctx.provider == "openai"  # forced even though Anthropic key is present


def test_pricing_includes_openai_models() -> None:
    from llm.budget import price_call
    from llm.client import LLMResponse, LLMUsage
    resp = LLMResponse(text="ok", usage=LLMUsage(input_tokens=1_000_000, output_tokens=1_000_000))
    cost_4o = price_call("gpt-4o", resp)
    assert 12.0 <= cost_4o <= 13.0  # $2.50 + $10 = $12.50
    cost_4o_mini = price_call("gpt-4o-mini", resp)
    assert 0.7 <= cost_4o_mini <= 0.8  # $0.15 + $0.60 = $0.75
