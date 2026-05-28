"""Generic, agent-agnostic profile model (v3 schema).

Replaces the SQL-agent-specific `RemoteConfig` in `agent_config.py`. An
`AgentProfile` describes any HTTP/GraphQL/MCP agent in terms its security
testers can reason about: discovered endpoints, inferred capabilities, an
auth scheme, and a risk tier derived from those capabilities.

Legacy configs still load via `migrate_remote_config()`.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, SecretStr, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class EndpointPurpose(str, Enum):
    """What an endpoint is FOR — testers key off this, not on path strings."""

    CHAT = "chat"
    TOOL_INVOKE = "tool_invoke"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    FILE_IO = "file_io"
    CODE_EXEC = "code_exec"
    HEALTH = "health"
    AUTH = "auth"
    UNKNOWN = "unknown"


class AgentCapability(str, Enum):
    """High-level things an agent can do. Drives test selection."""

    SQL_QUERY = "sql_query"
    EMAIL_SEND = "email_send"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    CODE_EXECUTION = "code_execution"
    WEB_BROWSE = "web_browse"
    SHELL_EXEC = "shell_exec"
    MEMORY_PERSIST = "memory_persist"
    SUBAGENT_DISPATCH = "subagent_dispatch"
    TOOL_INVOKE = "tool_invoke"
    UNKNOWN = "unknown"


class Transport(str, Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    MCP = "mcp"
    WEBSOCKET = "websocket"


class AuthScheme(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"


RiskTier = Literal["low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class ToolDescriptor(BaseModel):
    """A single tool/function the agent exposes (from manifest or OpenAPI op)."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    inferred_capability: AgentCapability = AgentCapability.UNKNOWN


class EndpointSpec(BaseModel):
    path: str
    method: HttpMethod
    purpose: EndpointPurpose = EndpointPurpose.UNKNOWN
    request_schema: dict[str, Any] | None = None
    response_schema: dict[str, Any] | None = None
    auth_required: bool = False
    tags: list[str] = Field(default_factory=list)
    operation_id: str | None = None
    summary: str | None = None


class AuthConfig(BaseModel):
    """Auth metadata. Secrets are NEVER inlined — always sourced from env."""

    scheme: AuthScheme = AuthScheme.NONE
    token_env_var: str | None = None
    header_name: str = "Authorization"
    header_prefix: str = "Bearer "  # used for BEARER
    refresh_endpoint: str | None = None

    # Resolved at runtime, never serialized. SecretStr keeps it out of dumps.
    _resolved_token: SecretStr | None = None

    @field_validator("scheme", mode="before")
    @classmethod
    def _coerce_scheme(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


class RateLimitConfig(BaseModel):
    """Token-bucket rate-limiter config for the target adapter.

    Algorithm is **token-bucket** (NOT sliding window). The bucket holds up
    to ``burst`` tokens and refills at ``requests_per_minute / 60`` tokens
    per second. ``invoke`` blocks until a token is available. On HTTP 429
    the adapter honors ``Retry-After`` then refunds the spent token and
    counts a retry attempt against ``max_retries_on_429``; once exhausted
    the tester gets ``TestStatus.TARGET_RATE_LIMITED``.
    """

    requests_per_minute: int = 60
    burst: int = 10
    max_retries_on_429: int = 3


class SessionHandle(BaseModel):
    """Per-tester multi-turn session state.

    Lifecycle is owned by ``TestRunner``, NOT by individual testers:

      1. Runner inspects ``@register_tester(multi_turn=True)``.
      2. Runner calls ``adapter.open_session() -> SessionHandle``.
      3. Runner injects the handle into the tester's ``run_tests(session=...)``.
      4. Tester appends to ``conversation`` via ``adapter.invoke_in_session(handle, ...)``.
      5. Runner calls ``adapter.close_session(handle)`` in a ``finally`` block.
      6. If ``@register_tester(requires_clean_state=True)``, runner calls
         ``adapter.reset_session()`` before the next tester runs.

    Stateless (single-turn) testers never see a SessionHandle — they take
    only the adapter and call ``adapter.invoke(...)`` directly.
    """

    session_id: str
    transport_session_token: str | None = None  # cookie / mcp session id
    conversation: list[dict[str, Any]] = Field(default_factory=list)
    opened_at_ms: int = 0
    extra: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# AgentProfile
# ---------------------------------------------------------------------------


class AgentProfile(BaseModel):
    """Top-level profile of a registered agent under test."""

    schema_version: Literal["3.0"] = "3.0"
    name: str
    agent_id: str = ""
    base_url: HttpUrl
    transport: Transport = Transport.REST
    auth: AuthConfig = Field(default_factory=AuthConfig)
    endpoints: list[EndpointSpec] = Field(default_factory=list)
    tools: list[ToolDescriptor] = Field(default_factory=list)
    inferred_capabilities: list[AgentCapability] = Field(default_factory=list)
    data_domains: list[str] = Field(default_factory=list)
    risk_tier: RiskTier = "low"
    risk_tier_source: Literal["inferred", "user"] = "inferred"
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    notes: str = ""

    # ---- Convenience -----------------------------------------------------

    def endpoints_for(self, purpose: EndpointPurpose) -> list[EndpointSpec]:
        return [e for e in self.endpoints if e.purpose == purpose]

    def has_capability(self, cap: AgentCapability) -> bool:
        return cap in self.inferred_capabilities


# ---------------------------------------------------------------------------
# risk_tier derivation
# ---------------------------------------------------------------------------


_CRITICAL_CAPS = {
    AgentCapability.CODE_EXECUTION,
    AgentCapability.SHELL_EXEC,
    AgentCapability.FILE_READ,
    AgentCapability.FILE_WRITE,
}
_HIGH_CAPS = {
    AgentCapability.SQL_QUERY,
    AgentCapability.EMAIL_SEND,
    AgentCapability.SUBAGENT_DISPATCH,
}
_HIGH_DOMAINS = {"financial", "healthcare", "pii", "payments", "legal"}
_MEDIUM_CAPS = {AgentCapability.MEMORY_PERSIST, AgentCapability.WEB_BROWSE}


def derive_risk_tier(
    capabilities: list[AgentCapability], data_domains: list[str]
) -> RiskTier:
    caps = set(capabilities)
    domains = {d.lower() for d in data_domains}
    if caps & _CRITICAL_CAPS:
        return "critical"
    if (caps & _HIGH_CAPS) or (domains & _HIGH_DOMAINS):
        return "high"
    if caps & _MEDIUM_CAPS:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Legacy migration
# ---------------------------------------------------------------------------


# Best-guess purpose classification for legacy endpoint keys. Anything not
# listed here lands as UNKNOWN and surfaces in the migration diff.
_LEGACY_PURPOSE_HINTS: dict[str, EndpointPurpose] = {
    "chat_endpoint": EndpointPurpose.CHAT,
    "stream_endpoint": EndpointPurpose.CHAT,
    "agent_stream_endpoint": EndpointPurpose.CHAT,
    "health_endpoint": EndpointPurpose.HEALTH,
}

_LEGACY_ADDITIONAL_HINTS: dict[str, EndpointPurpose] = {
    "forecast": EndpointPurpose.TOOL_INVOKE,
    "simulate": EndpointPurpose.TOOL_INVOKE,
    "train": EndpointPurpose.TOOL_INVOKE,
    "correct": EndpointPurpose.MEMORY_WRITE,
    "training_data": EndpointPurpose.MEMORY_READ,
    "schema": EndpointPurpose.MEMORY_READ,
    "schema_refresh": EndpointPurpose.MEMORY_WRITE,
    "cache_stats": EndpointPurpose.HEALTH,
    "cache_clear": EndpointPurpose.MEMORY_WRITE,
    "snapshots": EndpointPurpose.MEMORY_READ,
    "scheduler_trigger": EndpointPurpose.TOOL_INVOKE,
    "scheduler_pause": EndpointPurpose.TOOL_INVOKE,
    "scheduler_resume": EndpointPurpose.TOOL_INVOKE,
    "domain_profile": EndpointPurpose.MEMORY_READ,
    "activity": EndpointPurpose.MEMORY_READ,
    "delivery_health": EndpointPurpose.HEALTH,
}


def migrate_remote_config(legacy: Any) -> tuple[AgentProfile, list[str]]:
    """Translate a legacy ``AgentConfig`` (with embedded ``RemoteConfig``) into
    an ``AgentProfile``.

    Returns ``(profile, diff_lines)``. ``diff_lines`` is a human-readable list
    of decisions made during migration — emit on stderr so the user can review.
    """

    # Late import to avoid circular dependency at module import time.
    from .agent_config import AgentConfig, RemoteConfig

    if not isinstance(legacy, AgentConfig):
        raise TypeError(f"expected AgentConfig, got {type(legacy).__name__}")

    rc: RemoteConfig = legacy.remote_config
    diff: list[str] = []
    endpoints: list[EndpointSpec] = []

    # Named single endpoints
    for attr, purpose in _LEGACY_PURPOSE_HINTS.items():
        path = getattr(rc, attr, None)
        if not path:
            continue
        endpoints.append(
            EndpointSpec(
                path=path,
                method=HttpMethod.POST if purpose == EndpointPurpose.CHAT else HttpMethod.GET,
                purpose=purpose,
                auth_required=bool(legacy.auth_headers),
                tags=[attr],
            )
        )
        diff.append(f"  {attr} -> {purpose.value} ({path})")

    # additional_endpoints dict
    for key, path in (rc.additional_endpoints or {}).items():
        purpose = _LEGACY_ADDITIONAL_HINTS.get(key, EndpointPurpose.UNKNOWN)
        if purpose is EndpointPurpose.UNKNOWN:
            diff.append(f"  additional_endpoints.{key} -> UNKNOWN ({path})  [needs review]")
        else:
            diff.append(f"  additional_endpoints.{key} -> {purpose.value} ({path})")
        endpoints.append(
            EndpointSpec(
                path=path,
                method=HttpMethod.POST,
                purpose=purpose,
                auth_required=bool(legacy.auth_headers),
                tags=[key],
            )
        )

    # Tools
    tools = [
        ToolDescriptor(
            name=t.name,
            description=t.description,
            parameters=dict(t.parameters),
        )
        for t in legacy.tools_manifest
    ]
    # Infer capabilities from tool names (cheap heuristic; LLM can refine later).
    caps: set[AgentCapability] = set()
    for t in tools:
        n = t.name.lower()
        if "sql" in n or "query" in n or "schema" in n:
            caps.add(AgentCapability.SQL_QUERY)
        if "email" in n or "mail" in n:
            caps.add(AgentCapability.EMAIL_SEND)
        if "file" in n or "read" in n:
            caps.add(AgentCapability.FILE_READ)
        if "exec" in n or "run" in n or "shell" in n:
            caps.add(AgentCapability.CODE_EXECUTION)
        if "search" in n or "web" in n or "news" in n or "research" in n:
            caps.add(AgentCapability.WEB_BROWSE)
    if legacy.subagents:
        caps.add(AgentCapability.SUBAGENT_DISPATCH)
    if not caps:
        caps.add(AgentCapability.TOOL_INVOKE)

    # Auth — legacy stored headers directly. Convert to a NONE/BEARER skeleton;
    # the user must supply an env var to actually use a token at scan time.
    auth = AuthConfig(scheme=AuthScheme.BEARER if legacy.auth_headers else AuthScheme.NONE)
    if legacy.auth_headers:
        diff.append("  auth_headers detected: rerun with --auth-env to supply token via env var")

    data_domains: list[str] = []
    for tag_v in legacy.tags.values():
        v = str(tag_v).lower()
        if any(d in v for d in ("financial", "finance", "trading", "banking")):
            data_domains.append("financial")
    if any("sec_filing" in t.name.lower() or "financial" in t.name.lower() for t in tools):
        if "financial" not in data_domains:
            data_domains.append("financial")

    risk = derive_risk_tier(list(caps), data_domains)
    diff.append(f"  risk_tier inferred: {risk}")

    profile = AgentProfile(
        schema_version="3.0",
        name=legacy.name,
        agent_id=legacy.agent_id,
        base_url=rc.base_url,  # type: ignore[arg-type]
        transport=Transport.REST,
        auth=auth,
        endpoints=endpoints,
        tools=tools,
        inferred_capabilities=sorted(caps, key=lambda c: c.value),
        data_domains=data_domains,
        risk_tier=risk,
        risk_tier_source="inferred",
    )
    return profile, diff
