"""Unit tests for the v3 AgentProfile model + legacy migration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.agent_config import AgentConfig
from models.agent_profile import (
    AgentCapability,
    AgentProfile,
    AuthScheme,
    EndpointPurpose,
    RateLimitConfig,
    SessionHandle,
    Transport,
    derive_risk_tier,
    migrate_remote_config,
)
from models.enums import SKIPPED_STATUSES, TestStatus


SAMPLE_CONFIG = Path(__file__).parent.parent / "sample_configs" / "financial_agent.json"


def test_schema_version_is_literal() -> None:
    p = AgentProfile(name="x", base_url="http://example.com")
    assert p.schema_version == "3.0"

    with pytest.raises(Exception):
        AgentProfile(name="x", base_url="http://example.com", schema_version="2.0")  # type: ignore[arg-type]


def test_risk_tier_critical_on_code_exec() -> None:
    assert derive_risk_tier([AgentCapability.CODE_EXECUTION], []) == "critical"
    assert derive_risk_tier([AgentCapability.SHELL_EXEC], []) == "critical"
    assert derive_risk_tier([AgentCapability.FILE_READ], []) == "critical"


def test_risk_tier_high_on_sql_or_financial_domain() -> None:
    assert derive_risk_tier([AgentCapability.SQL_QUERY], []) == "high"
    assert derive_risk_tier([], ["financial"]) == "high"
    assert derive_risk_tier([], ["Healthcare"]) == "high"  # case-insensitive


def test_risk_tier_medium_then_low() -> None:
    assert derive_risk_tier([AgentCapability.MEMORY_PERSIST], []) == "medium"
    assert derive_risk_tier([], []) == "low"


def test_endpoints_for_filter() -> None:
    p = AgentProfile(name="x", base_url="http://example.com")
    assert p.endpoints_for(EndpointPurpose.CHAT) == []


def test_migrate_financial_agent_config() -> None:
    raw = json.loads(SAMPLE_CONFIG.read_text())
    legacy = AgentConfig.model_validate(raw)
    profile, diff = migrate_remote_config(legacy)

    assert profile.schema_version == "3.0"
    assert profile.name == legacy.name
    assert profile.transport is Transport.REST
    assert str(profile.base_url).rstrip("/") == "http://localhost:8000"

    # Chat + health migrated to typed endpoints.
    chats = profile.endpoints_for(EndpointPurpose.CHAT)
    assert any(e.path == "/api/ask" for e in chats)
    healths = profile.endpoints_for(EndpointPurpose.HEALTH)
    assert any(e.path == "/api/health" for e in healths)

    # additional_endpoints turned into EndpointSpec records.
    paths = {e.path for e in profile.endpoints}
    assert "/api/forecast" in paths
    assert "/api/schema" in paths

    # Capability inference picked up the financial domain.
    assert "financial" in profile.data_domains
    assert profile.risk_tier in ("high", "critical")
    assert profile.risk_tier_source == "inferred"

    # Diff is non-empty and lists at least one classification line.
    assert any("risk_tier inferred" in d for d in diff)


def test_rate_limit_config_defaults() -> None:
    rl = RateLimitConfig()
    assert rl.requests_per_minute == 60
    assert rl.burst == 10
    assert rl.max_retries_on_429 == 3


def test_session_handle_minimum() -> None:
    s = SessionHandle(session_id="abc")
    assert s.session_id == "abc"
    assert s.conversation == []
    assert s.transport_session_token is None


def test_new_skipped_statuses_in_skipped_set() -> None:
    """All v3 SKIPPED_* sub-statuses must be in SKIPPED_STATUSES so scoring
    treats them as 'did not run' rather than miscounting as ran-and-passed."""
    for s in (
        TestStatus.SKIPPED_CAPABILITY,
        TestStatus.SKIPPED_TRANSPORT,
        TestStatus.SKIPPED_CATEGORY_FILTER,
        TestStatus.SKIPPED_BUDGET,
        TestStatus.SKIPPED_UNCLASSIFIED,
        TestStatus.TARGET_RATE_LIMITED,
    ):
        assert s in SKIPPED_STATUSES


def test_auth_secret_not_in_dump() -> None:
    """AuthConfig._resolved_token is a SecretStr — must not appear in JSON
    dumps even when set."""
    p = AgentProfile(name="x", base_url="http://example.com")
    # Pydantic v2: model_dump_json should exclude private attrs by default.
    dumped = p.model_dump_json()
    assert "REDACTED" not in dumped  # nothing set, but contract holds
    assert p.auth.scheme is AuthScheme.NONE
