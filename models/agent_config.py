"""Pydantic models for agent registration and configuration."""

from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field


class ToolManifest(BaseModel):
    name: str
    description: str
    parameters: dict[str, str] = Field(default_factory=dict)


class RemoteConfig(BaseModel):
    base_url: str = "http://localhost:8080"
    chat_endpoint: str = "/api/ask"
    health_endpoint: str = "/api/health"
    stream_endpoint: str = "/api/ask/stream"
    agent_stream_endpoint: str = "/api/agent/stream"
    task_field: str = "question"
    response_field: str = "data"
    timeout_ms: int = 240000
    max_retries: int = 0
    extra_body: dict[str, Any] = Field(default_factory=dict)
    additional_endpoints: dict[str, str] = Field(default_factory=lambda: {
        "forecast": "/api/forecast",
        "simulate": "/api/simulate",
        "train": "/api/train",
        "correct": "/api/correct",
        "training_data": "/api/training-data",
        "schema": "/api/schema",
        "cache_stats": "/api/cache/stats",
        "cache_clear": "/api/cache/clear",
        "snapshots": "/api/snapshots",
        "scheduler_trigger": "/api/scheduler/trigger",
        "scheduler_pause": "/api/scheduler/pause",
        "scheduler_resume": "/api/scheduler/resume",
        "schema_refresh": "/api/schema/refresh",
        "domain_profile": "/api/domain-profile",
        "activity": "/api/activity",
        "delivery_health": "/api/delivery/health",
    })


class AgentConfig(BaseModel):
    """Agent registration configuration matching user-specified JSON format."""
    name: str
    agent_id: str = ""
    agent_type: str = "orchestrator"
    framework: str = "http"
    model_backbone: str = "qwen3:8b"
    memory_type: str = "vector_db"
    tools_manifest: list[ToolManifest] = Field(default_factory=list)
    subagents: list[str] = Field(default_factory=list)
    pass_k: int = 1
    max_cost_usd: float = 5.0
    sla_latency_ms: int = 1800000
    golden_milestones: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    remote_config: RemoteConfig = Field(default_factory=RemoteConfig)
    task_suite: list[str] = Field(default_factory=list)
    trigger: str = "manual"
    fail_on_threshold: bool = False
    auth_headers: dict[str, str] = Field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return self.remote_config.base_url

    @property
    def timeout_seconds(self) -> float:
        return self.remote_config.timeout_ms / 1000.0
