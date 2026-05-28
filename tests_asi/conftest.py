"""
Shared pytest-asyncio fixtures for ASI security tests.
Provides configured client, agent config, and baseline profile.
"""

import asyncio
import json
import os
import pytest
from pathlib import Path

from core.http_client import AsyncHttpClient
from core.health_checker import HealthChecker
from models.agent_config import AgentConfig
from models.test_result import BaselineProfile
from config.agent_registry import load_agent_config
from config.settings import DEFAULT_BASE_URL, SAMPLE_CONFIGS_DIR


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def agent_config() -> AgentConfig:
    """Load agent config from sample or environment."""
    config_path = os.getenv(
        "ASI_AGENT_CONFIG",
        str(SAMPLE_CONFIGS_DIR / "financial_agent.json")
    )
    if Path(config_path).exists():
        return load_agent_config(config_path)

    # Fallback to defaults
    return AgentConfig(
        name="financial-sql-agent",
        agent_id="test-session",
        remote_config={"base_url": DEFAULT_BASE_URL},
    )


@pytest.fixture(scope="session")
async def http_client(agent_config: AgentConfig) -> AsyncHttpClient:
    """Shared async HTTP client."""
    client = AsyncHttpClient(
        base_url=agent_config.base_url,
        timeout_s=agent_config.timeout_seconds,
        auth_headers=agent_config.auth_headers,
    )
    yield client
    await client.close()


@pytest.fixture(scope="session")
async def baseline_profile(
    http_client: AsyncHttpClient, agent_config: AgentConfig
) -> BaselineProfile:
    """Baseline latency profile from health check."""
    checker = HealthChecker(http_client, agent_config)
    status = await checker.check(run_baseline=True)
    return status.baseline
