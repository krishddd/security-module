"""Stateful multi-turn conversation abstraction (Gap #3).

Before this module, every "multi-turn" tester (goal drift, memory poisoning,
trust exploitation) issued a *sequence of independent* ``send_ask`` calls.
Each call was a fresh HTTP request with no conversation continuity, so a real
agent whose memory is keyed to a session — or a stateless chat-completions API
that only remembers what you resend in ``messages`` — never actually saw the
earlier turns. The chain *looked* multi-turn but tested one isolated slice.

``ConversationSession`` fixes that. It threads a single logical conversation
through the adapter's session (cookie/token continuity via
``adapter.invoke_in_session``) AND replays accumulated turns as a ``messages``
array for chat-completions-shaped endpoints. Either way, turn N genuinely sees
turns 1..N-1.

Testers obtain one via ``BaseASITester.conversation(session)`` and drive it with
``await convo.ask("...")`` or ``await convo.run_steps([...])``. The turn history
lives on ``convo.turns`` (role/content dicts) for drift scoring and evidence.

Design notes
------------
* Transport-agnostic: the session is constructed with an injected ``send_fn``
  (``async (payload) -> HttpResponse``) and a payload builder, so this module
  imports nothing from ``core.target_adapter`` and creates no import cycle.
* Backward-compatible: a tester that receives ``session=None`` (legacy
  ``run_all`` path, or a non-multi-turn caller) still gets a working session —
  it just falls back to per-turn ``invoke`` with no cross-request cookie
  continuity, plus ``messages`` replay where the endpoint supports it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from core.http_client import HttpResponse

logger = logging.getLogger(__name__)

# A send function maps a request payload to a structured HttpResponse.
SendFn = Callable[[dict[str, Any]], Awaitable[HttpResponse]]


@dataclass
class ProbeStep:
    """One declared turn in a multi-turn attack chain.

    Suites may build a ``list[ProbeStep]`` and hand it to
    ``ConversationSession.run_steps`` instead of calling ``ask`` imperatively.
    ``adversarial_markers`` and ``note`` are optional metadata carried into the
    per-turn record for evidence/scoring.
    """

    content: str
    adversarial_markers: list[str] = field(default_factory=list)
    note: str = ""


def endpoint_is_messages_shaped(endpoint: Any) -> bool:
    """True when the endpoint's request schema expects an OpenAI/Anthropic-style
    ``messages`` array. Such endpoints are stateless: continuity requires
    resending the full message history each turn."""
    schema = getattr(endpoint, "request_schema", None) or {}
    if not isinstance(schema, dict):
        return False
    props = schema.get("properties", {})
    if not isinstance(props, dict) or "messages" not in props:
        return False
    messages_prop = props.get("messages", {})
    return isinstance(messages_prop, dict) and messages_prop.get("type") == "array"


class ConversationSession:
    """A single logical multi-turn conversation with the target agent.

    Continuity is provided two ways, together:

    * **Session continuity** — every request goes through the same underlying
      adapter session (``send_fn`` routes to ``adapter.invoke_in_session``),
      so cookie/token-backed agents keep server-side memory across turns.
    * **History replay** — for ``messages``-shaped endpoints, each request
      carries the accumulated user+assistant turns, so stateless
      chat-completions agents also see the whole conversation.

    ``turns`` accumulates ``{"role": ..., "content": ...}`` for both the user
    prompts and the agent's replies, in order.
    """

    def __init__(
        self,
        *,
        send_fn: SendFn,
        messages_mode: bool,
        chat_field: str = "question",
        history_field: str = "messages",
        model_default: str = "gpt-3.5-turbo",
        handle: Any | None = None,
    ) -> None:
        self._send_fn = send_fn
        self.messages_mode = messages_mode
        self.chat_field = chat_field
        self.history_field = history_field
        self.model_default = model_default
        self.handle = handle
        # Ordered [{"role": "user"|"assistant", "content": str}, ...]
        self.turns: list[dict[str, str]] = []

    # ── driving the conversation ─────────────────────────────────────────

    async def ask(self, question: str) -> HttpResponse:
        """Send one user turn *in the context of every prior turn* and record
        both the prompt and the agent's reply."""
        self.turns.append({"role": "user", "content": question})
        payload = self._build_payload()
        resp = await self._send_fn(payload)
        answer = self._extract_answer(resp)
        self.turns.append({"role": "assistant", "content": answer})
        # NB: the adapter's SessionHandle transcript is written by
        # ``adapter.invoke_in_session`` (the send_fn), so we don't mirror here —
        # that would double-record. ``self.turns`` is the tester-facing history.
        return resp

    async def run_steps(self, steps: list[ProbeStep | str]) -> list[HttpResponse]:
        """Run a declared list of turns sequentially within this one session."""
        responses: list[HttpResponse] = []
        for step in steps:
            content = step.content if isinstance(step, ProbeStep) else step
            responses.append(await self.ask(content))
        return responses

    # ── history views ────────────────────────────────────────────────────

    @property
    def last_answer(self) -> str:
        for turn in reversed(self.turns):
            if turn["role"] == "assistant":
                return turn["content"]
        return ""

    @property
    def first_answer(self) -> str:
        for turn in self.turns:
            if turn["role"] == "assistant":
                return turn["content"]
        return ""

    @property
    def turn_count(self) -> int:
        """Number of user turns issued so far."""
        return sum(1 for t in self.turns if t["role"] == "user")

    def transcript(self) -> list[dict[str, str]]:
        """A copy of the full ordered transcript."""
        return [dict(t) for t in self.turns]

    # ── internals ────────────────────────────────────────────────────────

    def _build_payload(self) -> dict[str, Any]:
        """Build the request body for the *current* turn.

        ``messages`` mode resends the whole conversation (the assistant turns
        recorded so far plus the new trailing user turn). Flat mode sends only
        the latest user content and relies on the adapter session for state.
        """
        if self.messages_mode:
            return {
                "model": self.model_default,
                self.history_field: [
                    {"role": t["role"], "content": t["content"]} for t in self.turns
                ],
            }
        # Flat {field: latest-user-content}. self.turns[-1] is the user turn we
        # just appended in ask().
        return {self.chat_field: self.turns[-1]["content"]}

    @staticmethod
    def _extract_answer(resp: HttpResponse) -> str:
        """Pull the assistant's text out of a response for transcript replay."""
        text = getattr(resp, "raw_text", "") or ""
        if text:
            return text
        data = getattr(resp, "data", None)
        if isinstance(data, dict):
            inner = data.get("data", data)
            if isinstance(inner, dict):
                for key in ("answer", "response", "content", "message", "output", "text"):
                    val = inner.get(key)
                    if isinstance(val, str) and val:
                        return val
            return str(inner)
        return str(data) if data is not None else ""
