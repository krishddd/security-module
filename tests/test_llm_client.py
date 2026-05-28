"""ClaudeClient: prompt-cache contract + structural correctness.

No live API calls — every test stubs the anthropic SDK.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


def _mock_anthropic(monkeypatch: pytest.MonkeyPatch, *, captured: dict) -> None:
    """Replace anthropic.Anthropic with a stub that records call kwargs."""
    import sys

    class FakeMessages:
        def create(self, **kwargs):
            captured["kwargs"] = kwargs
            usage = SimpleNamespace(
                input_tokens=10, output_tokens=20,
                cache_creation_input_tokens=100,
                cache_read_input_tokens=200,
            )
            block = SimpleNamespace(type="text", text="ok")
            return SimpleNamespace(
                content=[block], stop_reason="end_turn",
                usage=usage, model=kwargs["model"],
            )

    class FakeAnthropic:
        def __init__(self, api_key: str):
            self.api_key = api_key
            self.messages = FakeMessages()
            self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[
                SimpleNamespace(id="claude-opus-4-7"),
                SimpleNamespace(id="claude-sonnet-4-6"),
            ]))

    fake_module = SimpleNamespace(Anthropic=FakeAnthropic)
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-1234567890")


def test_cache_contract_violation_blocks_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contract assertion fires when profile-like content appears in the system prompt."""
    captured: dict = {}
    _mock_anthropic(monkeypatch, captured=captured)

    # Force settings reload so the patched env var is picked up.
    import importlib, config.settings
    importlib.reload(config.settings)
    import llm.client
    importlib.reload(llm.client)

    client = llm.client.ClaudeClient()
    leaky_system = 'role: planner\n"base_url": "http://x"'  # explicit profile marker
    with pytest.raises(AssertionError, match="prompt-cache contract"):
        client.message(model="claude-sonnet-4-6", system=leaky_system, user="hi")


def test_system_prompt_is_cache_marked(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _mock_anthropic(monkeypatch, captured=captured)

    import importlib, config.settings, llm.client
    importlib.reload(config.settings); importlib.reload(llm.client)

    client = llm.client.ClaudeClient()
    client.message(model="claude-sonnet-4-6", system="static taxonomy here", user="dynamic profile here")

    sys_blocks = captured["kwargs"]["system"]
    assert isinstance(sys_blocks, list) and len(sys_blocks) == 1
    assert sys_blocks[0]["cache_control"] == {"type": "ephemeral"}
    assert sys_blocks[0]["text"] == "static taxonomy here"

    # User turn is the only place "profile" data lives.
    user_msgs = captured["kwargs"]["messages"]
    assert user_msgs[0]["role"] == "user"
    assert any("dynamic profile here" in b["text"] for b in user_msgs[0]["content"])


def test_usage_includes_cache_read_field(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _mock_anthropic(monkeypatch, captured=captured)

    import importlib, config.settings, llm.client
    importlib.reload(config.settings); importlib.reload(llm.client)

    client = llm.client.ClaudeClient()
    resp = client.message(model="claude-sonnet-4-6", system="static", user="hi")
    assert resp.usage.cache_read_input_tokens == 200
    assert resp.usage.cache_creation_input_tokens == 100


def test_model_id_validation_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _mock_anthropic(monkeypatch, captured=captured)

    import importlib, config.settings, llm.client
    monkeypatch.setenv("ASI_LLM_MODEL_PLANNER", "claude-opus-4-7")
    monkeypatch.setenv("ASI_LLM_MODEL_PAYLOAD", "claude-sonnet-4-6")
    monkeypatch.setenv("ASI_LLM_MODEL_TRIAGE", "claude-sonnet-4-6")
    importlib.reload(config.settings); importlib.reload(llm.client)

    # Should not raise.
    llm.client.ClaudeClient(validate_models=True)


def test_model_id_validation_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _mock_anthropic(monkeypatch, captured=captured)

    import importlib, config.settings, llm.client
    monkeypatch.setenv("ASI_LLM_MODEL_PLANNER", "claude-imaginary-99")
    importlib.reload(config.settings); importlib.reload(llm.client)

    with pytest.raises(llm.client.LLMUnavailableError, match="not found on API"):
        llm.client.ClaudeClient(validate_models=True)


def test_no_api_key_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}
    _mock_anthropic(monkeypatch, captured=captured)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    import importlib, config.settings, llm.client
    importlib.reload(config.settings); importlib.reload(llm.client)

    with pytest.raises(llm.client.LLMUnavailableError, match="ANTHROPIC_API_KEY"):
        llm.client.ClaudeClient()
