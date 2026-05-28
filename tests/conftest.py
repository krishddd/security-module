"""Shared pytest fixtures for the v3 test suite."""

from __future__ import annotations

import pytest

from tests.fixtures.stub_agent.server import stub_agent_running


@pytest.fixture(scope="session")
def stub_agent_url() -> str:  # type: ignore[misc]
    """Session-scoped: starts the FastAPI stub agent once, tears down at end."""
    with stub_agent_running() as url:
        yield url
