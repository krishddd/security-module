"""Backward-compatibility loader for legacy ``AgentConfig`` JSON files.

Delegates to ``models.agent_profile.migrate_remote_config``.
"""

from __future__ import annotations

import json
from pathlib import Path

from models.agent_config import AgentConfig
from models.agent_profile import AgentProfile, migrate_remote_config


def load_legacy_config(path: str | Path) -> tuple[AgentProfile, list[str]]:
    """Load a v1/v2 ``AgentConfig`` JSON and return ``(profile, migration_diff)``.

    Caller is expected to print the diff lines to stderr so the user can
    review any UNKNOWN classifications.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    legacy = AgentConfig.model_validate(raw)
    return migrate_remote_config(legacy)
