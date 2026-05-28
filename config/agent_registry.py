"""Load, validate, and save agent registration configurations."""

from __future__ import annotations
import json
import uuid
import logging
from pathlib import Path

from models.agent_config import AgentConfig

logger = logging.getLogger(__name__)


def load_agent_config(path: str | Path) -> AgentConfig:
    """Load and validate an agent config from a JSON file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Agent config not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Handle split config format (separate base_url/health configs)
    if isinstance(raw, list):
        merged = {}
        for item in raw:
            merged.update(item)
        raw = merged

    # Auto-generate agent_id if not present
    if "agent_id" not in raw or not raw["agent_id"]:
        raw["agent_id"] = str(uuid.uuid4())

    config = AgentConfig.model_validate(raw)
    logger.info(f"Loaded agent config: {config.name} ({config.agent_id})")
    return config


def save_agent_config(config: AgentConfig, path: str | Path) -> Path:
    """Save agent config to JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config.model_dump(), f, indent=2)
    logger.info(f"Saved agent config to {path}")
    return path
