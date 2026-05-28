"""OpenAPI 3.x / Swagger 2.0 → AgentProfile.

Fetches a spec document, normalizes paths and operations into
``EndpointSpec`` records, infers ``EndpointPurpose`` from operation IDs /
tags / paths, infers ``AgentCapability`` from operation summaries +
parameter schemas, and produces a fully-populated ``AgentProfile``.

SSRF guard runs before any network call — callers must pass
``allow_internal=True`` to scan localhost.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from core.ssrf_guard import assert_url_safe
from models.agent_profile import (
    AgentCapability,
    AgentProfile,
    AuthConfig,
    AuthScheme,
    EndpointPurpose,
    EndpointSpec,
    HttpMethod,
    ToolDescriptor,
    Transport,
    derive_risk_tier,
)


class OpenAPIParseError(ValueError):
    """Raised on malformed or unsupported OpenAPI documents."""


# ---------------------------------------------------------------------------
# Purpose / capability heuristics
# ---------------------------------------------------------------------------

# Substring → EndpointPurpose. First match wins. Order matters: more specific
# tokens come before generic ones (e.g. "health" before "status").
_PURPOSE_HINTS: list[tuple[str, EndpointPurpose]] = [
    ("health", EndpointPurpose.HEALTH),
    ("healthz", EndpointPurpose.HEALTH),
    ("ready", EndpointPurpose.HEALTH),
    ("ping", EndpointPurpose.HEALTH),
    ("status", EndpointPurpose.HEALTH),
    ("login", EndpointPurpose.AUTH),
    ("logout", EndpointPurpose.AUTH),
    ("token", EndpointPurpose.AUTH),
    ("oauth", EndpointPurpose.AUTH),
    ("auth", EndpointPurpose.AUTH),
    ("session", EndpointPurpose.AUTH),
    ("chat", EndpointPurpose.CHAT),
    ("ask", EndpointPurpose.CHAT),
    ("message", EndpointPurpose.CHAT),
    ("completion", EndpointPurpose.CHAT),
    ("converse", EndpointPurpose.CHAT),
    ("query", EndpointPurpose.CHAT),
    ("file", EndpointPurpose.FILE_IO),
    ("upload", EndpointPurpose.FILE_IO),
    ("download", EndpointPurpose.FILE_IO),
    ("exec", EndpointPurpose.CODE_EXEC),
    ("run", EndpointPurpose.CODE_EXEC),
    ("eval", EndpointPurpose.CODE_EXEC),
    ("memory", EndpointPurpose.MEMORY_READ),
    ("history", EndpointPurpose.MEMORY_READ),
    ("retrieve", EndpointPurpose.MEMORY_READ),
    ("remember", EndpointPurpose.MEMORY_WRITE),
    ("store", EndpointPurpose.MEMORY_WRITE),
    ("save", EndpointPurpose.MEMORY_WRITE),
    ("tool", EndpointPurpose.TOOL_INVOKE),
    ("function", EndpointPurpose.TOOL_INVOKE),
    ("action", EndpointPurpose.TOOL_INVOKE),
]

# Substring → AgentCapability. Applied to operation summary + path + tags.
_CAPABILITY_HINTS: list[tuple[str, AgentCapability]] = [
    ("sql", AgentCapability.SQL_QUERY),
    ("query", AgentCapability.SQL_QUERY),
    ("database", AgentCapability.SQL_QUERY),
    ("email", AgentCapability.EMAIL_SEND),
    ("mail", AgentCapability.EMAIL_SEND),
    ("send", AgentCapability.EMAIL_SEND),
    ("file_read", AgentCapability.FILE_READ),
    ("file/read", AgentCapability.FILE_READ),
    ("download", AgentCapability.FILE_READ),
    ("upload", AgentCapability.FILE_WRITE),
    ("write", AgentCapability.FILE_WRITE),
    ("exec", AgentCapability.CODE_EXECUTION),
    ("eval", AgentCapability.CODE_EXECUTION),
    ("shell", AgentCapability.SHELL_EXEC),
    ("command", AgentCapability.SHELL_EXEC),
    ("browse", AgentCapability.WEB_BROWSE),
    ("fetch", AgentCapability.WEB_BROWSE),
    ("scrape", AgentCapability.WEB_BROWSE),
    ("search", AgentCapability.WEB_BROWSE),
    ("memory", AgentCapability.MEMORY_PERSIST),
    ("subagent", AgentCapability.SUBAGENT_DISPATCH),
    ("delegate", AgentCapability.SUBAGENT_DISPATCH),
]


def _classify_purpose(path: str, method: str, op_id: str, tags: list[str]) -> EndpointPurpose:
    haystack = " ".join([path, method, op_id, *tags]).lower()
    for needle, purpose in _PURPOSE_HINTS:
        if needle in haystack:
            return purpose
    return EndpointPurpose.UNKNOWN


def _classify_capabilities(operation: dict[str, Any], path: str) -> set[AgentCapability]:
    summary = str(operation.get("summary", "")).lower()
    description = str(operation.get("description", "")).lower()
    tags = " ".join(operation.get("tags", []) or []).lower()
    op_id = str(operation.get("operationId", "")).lower()
    haystack = " ".join([summary, description, tags, op_id, path.lower()])
    caps: set[AgentCapability] = set()
    for needle, cap in _CAPABILITY_HINTS:
        if needle in haystack:
            caps.add(cap)
    return caps


# ---------------------------------------------------------------------------
# Auth scheme extraction
# ---------------------------------------------------------------------------


def _extract_auth(spec: dict[str, Any]) -> AuthConfig:
    """Pull the first declared securityScheme. v3.0 location: components.securitySchemes."""
    schemes = (
        spec.get("components", {}).get("securitySchemes")
        or spec.get("securityDefinitions")  # swagger 2.0
        or {}
    )
    for _name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        stype = str(scheme.get("type", "")).lower()
        if stype == "http" and str(scheme.get("scheme", "")).lower() == "bearer":
            return AuthConfig(scheme=AuthScheme.BEARER, header_name="Authorization")
        if stype == "http" and str(scheme.get("scheme", "")).lower() == "basic":
            return AuthConfig(scheme=AuthScheme.BASIC, header_name="Authorization", header_prefix="Basic ")
        if stype == "apikey":
            header = scheme.get("name", "X-API-Key")
            return AuthConfig(scheme=AuthScheme.API_KEY, header_name=header, header_prefix="")
        if stype == "oauth2":
            return AuthConfig(scheme=AuthScheme.OAUTH2, header_name="Authorization")
    return AuthConfig(scheme=AuthScheme.NONE)


# ---------------------------------------------------------------------------
# Base URL resolution
# ---------------------------------------------------------------------------


def _resolve_base_url(spec: dict[str, Any], spec_url: str | None) -> str:
    # OpenAPI 3.x
    servers = spec.get("servers") or []
    if servers and isinstance(servers, list):
        first = servers[0]
        if isinstance(first, dict) and first.get("url"):
            url = str(first["url"])
            if url.startswith("/") and spec_url:
                # Relative server URL — resolve against spec_url
                p = urlparse(spec_url)
                return f"{p.scheme}://{p.netloc}{url.rstrip('/')}"
            if url.startswith("http"):
                return url.rstrip("/")
    # Swagger 2.0
    host = spec.get("host")
    if host:
        schemes = spec.get("schemes") or ["https"]
        base_path = spec.get("basePath", "")
        return f"{schemes[0]}://{host}{base_path}".rstrip("/")
    # Fall back to spec_url's origin
    if spec_url:
        p = urlparse(spec_url)
        return f"{p.scheme}://{p.netloc}"
    raise OpenAPIParseError("could not determine base_url (no servers/host and no spec_url)")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_\-]")


def parse_openapi(spec: dict[str, Any], *, name: str, spec_url: str | None = None) -> AgentProfile:
    """Convert a parsed OpenAPI dict into an ``AgentProfile``."""
    if not isinstance(spec, dict):
        raise OpenAPIParseError("spec must be a JSON object")
    if "paths" not in spec:
        raise OpenAPIParseError("spec has no 'paths' (not a valid OpenAPI/Swagger document)")

    base_url = _resolve_base_url(spec, spec_url)
    auth = _extract_auth(spec)
    endpoints: list[EndpointSpec] = []
    tools: list[ToolDescriptor] = []
    all_caps: set[AgentCapability] = set()
    requires_auth_globally = bool(spec.get("security"))

    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            method_u = method.upper()
            if method_u not in HttpMethod.__members__:
                continue
            if not isinstance(op, dict):
                continue

            op_id = str(op.get("operationId") or "")
            tags = [str(t) for t in (op.get("tags") or [])]
            summary = op.get("summary") or op_id or f"{method_u} {path}"
            purpose = _classify_purpose(path, method_u, op_id, tags)
            caps_here = _classify_capabilities(op, path)
            all_caps |= caps_here

            request_schema = None
            rb = op.get("requestBody", {})
            if isinstance(rb, dict):
                content = rb.get("content", {})
                # Prefer JSON; fall back to first declared.
                preferred = content.get("application/json") or next(iter(content.values()), None)
                if isinstance(preferred, dict):
                    request_schema = preferred.get("schema")

            response_schema = None
            responses = op.get("responses") or {}
            ok_resp = responses.get("200") or responses.get("default")
            if isinstance(ok_resp, dict):
                content = ok_resp.get("content", {})
                preferred = content.get("application/json") or next(iter(content.values()), None)
                if isinstance(preferred, dict):
                    response_schema = preferred.get("schema")

            auth_required = requires_auth_globally or bool(op.get("security"))

            endpoints.append(
                EndpointSpec(
                    path=path,
                    method=HttpMethod(method_u),
                    purpose=purpose,
                    request_schema=request_schema,
                    response_schema=response_schema,
                    auth_required=auth_required,
                    tags=tags,
                    operation_id=op_id or None,
                    summary=str(summary)[:200] or None,
                )
            )

            # Each tool-invoke / chat operation becomes a ToolDescriptor so
            # the planner can reason about per-tool capabilities.
            if purpose in (EndpointPurpose.TOOL_INVOKE, EndpointPurpose.CHAT, EndpointPurpose.CODE_EXEC, EndpointPurpose.FILE_IO):
                tool_name = op_id or _SAFE_NAME_RE.sub("_", f"{method_u}_{path}").strip("_")
                tools.append(
                    ToolDescriptor(
                        name=tool_name[:80],
                        description=str(summary)[:300],
                        parameters=(request_schema or {}).get("properties", {})
                        if isinstance(request_schema, dict) else {},
                        inferred_capability=(next(iter(caps_here)) if caps_here else AgentCapability.UNKNOWN),
                    )
                )

    if not endpoints:
        raise OpenAPIParseError("spec contained no usable operations")

    if not all_caps:
        all_caps.add(AgentCapability.TOOL_INVOKE)

    risk = derive_risk_tier(list(all_caps), [])

    return AgentProfile(
        schema_version="3.0",
        name=name,
        base_url=base_url,
        transport=Transport.REST,
        auth=auth,
        endpoints=endpoints,
        tools=tools,
        inferred_capabilities=sorted(all_caps, key=lambda c: c.value),
        data_domains=[],
        risk_tier=risk,
        risk_tier_source="inferred",
    )


def parse_openapi_url(
    spec_url: str,
    *,
    name: str | None = None,
    allow_internal: bool = False,
    timeout_s: float = 15.0,
) -> AgentProfile:
    """Fetch an OpenAPI document and return an ``AgentProfile``.

    Supports two URL schemes:
      * ``http(s)://...`` — SSRF-guarded HTTP fetch (default path).
      * ``file:///abs/path`` or a bare local filesystem path — load from disk.
        Useful when the target agent doesn't serve its spec over HTTP (e.g.
        AnythingLLM ships the JSON inside its container but only mounts a
        Swagger UI HTML page at /api/docs). Pair with `docker cp` to extract.

    SSRF guard only runs for HTTP URLs.
    """
    if spec_url.startswith("file://") or _looks_like_local_path(spec_url):
        return _parse_openapi_from_file(spec_url, name=name)

    assert_url_safe(spec_url, allow_internal=allow_internal)
    with httpx.Client(timeout=timeout_s, follow_redirects=False) as client:
        resp = client.get(spec_url)
        resp.raise_for_status()
        try:
            spec = resp.json()
        except json.JSONDecodeError as e:
            raise OpenAPIParseError(f"spec at {spec_url} is not valid JSON: {e}") from e
    return parse_openapi(spec, name=name or _infer_name(spec_url), spec_url=spec_url)


def _looks_like_local_path(s: str) -> bool:
    """Detect bare local-path strings (Windows drive, leading ./ or /)."""
    if len(s) >= 3 and s[1:3] == ":\\":      # Windows: C:\...
        return True
    if len(s) >= 3 and s[1:3] == ":/":       # Windows: C:/...
        return True
    if s.startswith(("./", "../", "/")):
        return True
    return False


def _parse_openapi_from_file(spec_url: str, *, name: str | None = None) -> AgentProfile:
    """Load an OpenAPI spec from a local file (file:// URL or bare path)."""
    from pathlib import Path

    if spec_url.startswith("file://"):
        # Strip the scheme; on Windows file:///C:/foo -> /C:/foo, fix that.
        path_str = spec_url[len("file://"):]
        if path_str.startswith("/") and len(path_str) >= 4 and path_str[2] == ":":
            path_str = path_str[1:]   # /C:/foo -> C:/foo
    else:
        path_str = spec_url

    path = Path(path_str)
    if not path.is_file():
        raise OpenAPIParseError(f"spec file not found: {path}")
    try:
        spec = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise OpenAPIParseError(f"spec at {path} is not valid JSON: {e}") from e
    # Synthetic spec_url so a spec with only relative server URLs (e.g.
    # AnythingLLM's "servers: [{url: '/api'}]") can be resolved. The caller
    # is expected to override base_url on the resulting profile.
    return parse_openapi(spec, name=name or path.stem, spec_url="http://127.0.0.1")


def _infer_name(spec_url: str) -> str:
    host = urlparse(spec_url).hostname or "agent"
    return host.split(":")[0]
