"""Sample profiles in sample_configs/ must always parse as valid v3 profiles.

Guards against drift between the schema and the example files we ship.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.agent_profile import AgentProfile

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "sample_configs"

V3_SAMPLES = [
    "generic_rest_agent.json",
    "stub_agent_profile_example.json",
    "dvaa_agent.json",
    "full_vuln_agent.json",
    "ollama_agent.json",
    "dify_agent.json",
    "odysseus_agent.json",
]


@pytest.mark.parametrize("filename", V3_SAMPLES)
def test_v3_sample_parses(filename: str) -> None:
    raw = json.loads((SAMPLE_DIR / filename).read_text(encoding="utf-8"))
    # Drop comment fields not in schema.
    raw = {k: v for k, v in raw.items() if not k.startswith("_")}
    profile = AgentProfile.model_validate(raw)
    assert profile.schema_version == "3.0"
    assert profile.endpoints, f"{filename}: should have at least one endpoint"


def test_stub_sample_matches_inferred_risk_tier() -> None:
    """The stub example claims risk_tier=critical because it has SQL + file
    capabilities. Verify the derivation rule still agrees."""
    raw = json.loads((SAMPLE_DIR / "stub_agent_profile_example.json").read_text(encoding="utf-8"))
    raw = {k: v for k, v in raw.items() if not k.startswith("_")}
    profile = AgentProfile.model_validate(raw)

    from models.agent_profile import derive_risk_tier
    inferred = derive_risk_tier(profile.inferred_capabilities, profile.data_domains)
    assert inferred == "critical"
    assert profile.risk_tier == "critical"
