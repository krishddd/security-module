"""
Pre-flight health checker with baseline latency profiling.
Establishes performance baselines used by ASI08 for DoS threshold calculations.
"""

from __future__ import annotations
import asyncio
import logging
import math
from dataclasses import dataclass, field
from typing import Any

from core.http_client import AsyncHttpClient
from models.agent_config import AgentConfig
from models.test_result import BaselineProfile
from config.settings import BASELINE_SAMPLES, BASELINE_QUERY, BASELINE_MULTIPLIER

logger = logging.getLogger(__name__)


@dataclass
class EndpointStatus:
    path: str
    reachable: bool
    status_code: int = 0
    latency_ms: float = 0.0
    detail: str = ""


@dataclass
class HealthStatus:
    healthy: bool = False
    agent_info: dict[str, Any] = field(default_factory=dict)
    endpoints: list[EndpointStatus] = field(default_factory=list)
    baseline: BaselineProfile = field(default_factory=BaselineProfile)

    @property
    def available_endpoints(self) -> list[str]:
        return [e.path for e in self.endpoints if e.reachable]

    @property
    def unavailable_endpoints(self) -> list[str]:
        return [e.path for e in self.endpoints if not e.reachable]


class HealthChecker:
    """Pre-flight health check and baseline profiling."""

    def __init__(self, client: AsyncHttpClient, config: AgentConfig):
        self.client = client
        self.config = config

    async def check(self, run_baseline: bool = True) -> HealthStatus:
        status = HealthStatus()

        # 1. Check health endpoint
        health_resp = await self.client.get_json(
            self.config.remote_config.health_endpoint
        )
        health_ep = EndpointStatus(
            path=self.config.remote_config.health_endpoint,
            reachable=health_resp.ok,
            status_code=health_resp.status_code,
            latency_ms=health_resp.latency_ms,
        )
        status.endpoints.append(health_ep)

        if not health_resp.ok:
            status.healthy = False
            health_ep.detail = f"Health check failed: {health_resp.data}"
            logger.error(f"Health check failed: {health_resp.status_code}")
            return status

        status.agent_info = health_resp.data
        status.healthy = True
        logger.info("Health endpoint OK")

        # 2. Probe additional endpoints
        probes = []
        for name, path in self.config.remote_config.additional_endpoints.items():
            probes.append(self._probe_endpoint(name, path))

        probe_results = await asyncio.gather(*probes, return_exceptions=True)
        for result in probe_results:
            if isinstance(result, EndpointStatus):
                status.endpoints.append(result)

        available = len(status.available_endpoints)
        total = len(status.endpoints)
        logger.info(f"Endpoint probe: {available}/{total} reachable")

        # 3. Baseline latency profiling
        if run_baseline:
            status.baseline = await self._profile_baseline()

        return status

    async def _probe_endpoint(self, name: str, path: str) -> EndpointStatus:
        """Probe a single endpoint for reachability."""
        try:
            resp = await self.client.get_json(path)
            return EndpointStatus(
                path=path,
                reachable=resp.ok or resp.status_code == 405,  # 405 = exists but wrong method
                status_code=resp.status_code,
                latency_ms=resp.latency_ms,
                detail=name,
            )
        except Exception as e:
            return EndpointStatus(
                path=path, reachable=False, detail=f"{name}: {e}"
            )

    async def _profile_baseline(self) -> BaselineProfile:
        """
        Establish latency baseline by running N simple queries.
        Used by ASI08 to compute DoS thresholds: success = latency > p95 * BASELINE_MULTIPLIER.
        """
        logger.info(f"Profiling baseline with {BASELINE_SAMPLES} samples...")
        latencies = []

        for i in range(BASELINE_SAMPLES):
            resp = await self.client.post_json(
                self.config.remote_config.chat_endpoint,
                {self.config.remote_config.task_field: BASELINE_QUERY}
            )
            if resp.ok:
                latencies.append(resp.latency_ms)
                logger.info(f"  Baseline sample {i+1}: {resp.latency_ms:.0f}ms")
            else:
                logger.warning(f"  Baseline sample {i+1} failed: {resp.status_code}")

        if not latencies:
            logger.warning("No successful baseline samples — using defaults")
            return BaselineProfile(
                mean_ms=240000, p95_ms=240000, stddev_ms=0,
                samples=0, baseline_query=BASELINE_QUERY,
            )

        mean = sum(latencies) / len(latencies)
        sorted_lat = sorted(latencies)
        p95_idx = int(math.ceil(0.95 * len(sorted_lat))) - 1
        p95 = sorted_lat[max(0, p95_idx)]
        variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
        stddev = math.sqrt(variance)

        profile = BaselineProfile(
            mean_ms=mean, p95_ms=p95, stddev_ms=stddev,
            samples=len(latencies), baseline_query=BASELINE_QUERY,
        )
        logger.info(
            f"Baseline: mean={mean:.0f}ms p95={p95:.0f}ms "
            f"stddev={stddev:.0f}ms (DoS threshold={p95 * BASELINE_MULTIPLIER:.0f}ms)"
        )
        return profile
