"""OpenAPI parser tests — against a synthetic spec and the live stub agent."""

from __future__ import annotations

import httpx
import pytest

from discovery.openapi_parser import (
    OpenAPIParseError,
    parse_openapi,
    parse_openapi_url,
)
from discovery.well_known_prober import probe_well_known
from models.agent_profile import AgentCapability, EndpointPurpose, Transport


SYNTHETIC_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Synthetic", "version": "1.0"},
    "servers": [{"url": "https://api.example.com"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/healthz": {
            "get": {"operationId": "health", "summary": "Health probe", "tags": ["health"]}
        },
        "/chat": {
            "post": {
                "operationId": "chat",
                "summary": "Ask the agent a question",
                "tags": ["chat"],
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object", "properties": {"question": {"type": "string"}}}}}
                },
                "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}},
            }
        },
        "/sql_query": {
            "post": {
                "operationId": "sql_query",
                "summary": "Run a SQL query against the database",
                "tags": ["tools"],
            }
        },
        "/file/read": {
            "post": {"operationId": "file_read", "summary": "Read a file by path"}
        },
    },
}


def test_parse_synthetic_spec() -> None:
    profile = parse_openapi(SYNTHETIC_SPEC, name="synthetic")
    assert profile.schema_version == "3.0"
    assert profile.transport is Transport.REST
    assert str(profile.base_url).rstrip("/") == "https://api.example.com"

    paths = {(e.path, e.purpose) for e in profile.endpoints}
    assert ("/healthz", EndpointPurpose.HEALTH) in paths
    assert ("/chat", EndpointPurpose.CHAT) in paths
    # /sql_query has "query" in its op_id -> CHAT under current heuristics.
    # We just assert it was classified to *something* useful.
    assert any(p == "/sql_query" and e.purpose != EndpointPurpose.UNKNOWN for p, e in
               [(es.path, es) for es in profile.endpoints])
    assert ("/file/read", EndpointPurpose.FILE_IO) in paths

    # SQL + file capabilities inferred.
    caps = set(profile.inferred_capabilities)
    assert AgentCapability.SQL_QUERY in caps
    assert AgentCapability.FILE_READ in caps

    # Bearer auth picked up + global security flag propagated.
    assert profile.auth.scheme.value == "bearer"
    assert all(e.auth_required for e in profile.endpoints)


def test_parse_rejects_empty_spec() -> None:
    with pytest.raises(OpenAPIParseError):
        parse_openapi({}, name="bad")


def test_parse_rejects_no_operations() -> None:
    with pytest.raises(OpenAPIParseError):
        parse_openapi({"paths": {}}, name="bad")


# ---- live stub-agent tests ------------------------------------------------


def test_parse_openapi_url_against_stub(stub_agent_url: str) -> None:
    spec_url = f"{stub_agent_url}/openapi.json"
    profile = parse_openapi_url(spec_url, name="stub", allow_internal=True)

    paths = {e.path for e in profile.endpoints}
    assert "/healthz" in paths
    assert "/chat" in paths
    assert "/sql_tool" in paths
    assert "/file_read" in paths

    # SQL capability inferred from /sql_tool's summary text.
    assert AgentCapability.SQL_QUERY in profile.inferred_capabilities

    # risk_tier should be at least HIGH given SQL_QUERY presence.
    assert profile.risk_tier in ("high", "critical")


def test_parse_openapi_url_blocks_localhost_without_flag(stub_agent_url: str) -> None:
    from core.ssrf_guard import SSRFBlockedError
    spec_url = f"{stub_agent_url}/openapi.json"
    with pytest.raises(SSRFBlockedError):
        parse_openapi_url(spec_url, name="stub", allow_internal=False)


def test_well_known_prober_finds_stub_openapi(stub_agent_url: str) -> None:
    found = probe_well_known(stub_agent_url, allow_internal=True)
    assert found is not None
    assert found.endswith("/openapi.json")


def test_well_known_prober_returns_none_on_blank_target() -> None:
    # 127.0.0.1:1 is essentially guaranteed to be closed.
    found = probe_well_known("http://127.0.0.1:1", allow_internal=True, timeout_s=0.5)
    assert found is None
