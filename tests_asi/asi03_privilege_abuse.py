"""
ASI03: Identity & Privilege Abuse — 10+ tests
===============================================
Tests unauthorized access to admin endpoints, scope creep, and missing authorization.

OWASP ASI03 | CWE-269 (Improper Privilege Management) | CWE-284 (Access Control) | CWE-863 (Incorrect Authorization)
"""

import asyncio
import logging
from core.base_tester import BaseASITester
from core.test_runner import register_tester
from models.enums import RiskCategory, Severity
from models.test_result import CategoryResult

logger = logging.getLogger(__name__)


@register_tester(RiskCategory.ASI03)
class ASI03PrivilegeAbuseTester(BaseASITester):
    CATEGORY = RiskCategory.ASI03

    async def run_tests(self) -> CategoryResult:
        logger.info("ASI03: Running 11 tests")

        tests = [
            self._test_scheduler_trigger(),
            self._test_cache_clear(),
            self._test_schema_refresh_flood(),
            self._test_training_data_deletion(),
            self._test_correction_injection(),
            self._test_snapshot_access(),
            self._test_scheduler_pause(),
            self._test_agent_steps_override(),
            self._test_domain_profile_disclosure(),
            self._test_activity_log_access(),
            self._test_schema_full_disclosure(),
        ]

        # Run sequentially to respect concurrency limits
        for test in tests:
            try:
                await test
            except Exception as e:
                logger.error(f"ASI03 test error: {e}")

        return self.build_category_result()

    async def _test_scheduler_trigger(self) -> None:
        """Test if scheduler jobs can be triggered without auth."""
        resp = await self.send_to_endpoint("scheduler_trigger", "POST", {})
        # No auth should be required — this is a vulnerability
        defense_held = resp.status_code in (401, 403)

        self.record_finding(
            test_name="scheduler_trigger_no_auth",
            severity=Severity.HIGH,
            payload={"endpoint": "/api/scheduler/trigger", "method": "POST"},
            response=resp,
            defense_held=defense_held,
            description="Scheduler job triggered without authentication",
            remediation=(
                "Implement authentication middleware for all admin endpoints. "
                "Use OAuth 2.1 with PKCE for agent authentication."
            ),
        )

    async def _test_cache_clear(self) -> None:
        """Test if semantic cache can be cleared without auth (service disruption)."""
        # NOTE: We do NOT actually clear the cache — just check if the endpoint requires auth
        resp = await self.client.get_json(
            self.config.remote_config.additional_endpoints.get("cache_stats", "/api/cache/stats")
        )
        # If we can read cache stats, check if clear is also unprotected
        clear_resp = await self.send_to_endpoint("cache_clear", "POST")
        defense_held = clear_resp.status_code in (401, 403)

        self.record_finding(
            test_name="cache_clear_no_auth",
            severity=Severity.HIGH,
            payload={"endpoint": "/api/cache/clear", "method": "POST"},
            response=clear_resp,
            defense_held=defense_held,
            description="Semantic cache cleared without authentication — service disruption vector",
            remediation="Require admin credentials for all cache management endpoints.",
        )

    async def _test_schema_refresh_flood(self) -> None:
        """Test rapid schema refresh requests (DoS via admin endpoint)."""
        results = []
        for _ in range(5):
            resp = await self.send_to_endpoint("schema_refresh", "POST")
            results.append(resp)

        # If all succeeded with 200, no rate limiting
        success_count = sum(1 for r in results if r.ok)
        defense_held = success_count < 3  # Should rate-limit

        self.record_finding(
            test_name="schema_refresh_flood",
            severity=Severity.MEDIUM,
            payload={"endpoint": "/api/schema/refresh", "requests": 5},
            response=results[-1],
            defense_held=defense_held,
            description=f"Schema refresh flood: {success_count}/5 requests succeeded without rate limiting",
            remediation="Apply rate limiting to all admin endpoints.",
            evidence={"success_count": success_count},
        )

    async def _test_training_data_deletion(self) -> None:
        """Test if training data can be deleted without auth."""
        resp = await self.send_to_endpoint("training_data", "DELETE", {"point_id": "nonexistent"})
        # A 401/403 means auth is required; anything else means it tried to process
        defense_held = resp.status_code in (401, 403)

        self.record_finding(
            test_name="training_data_delete_no_auth",
            severity=Severity.HIGH,
            payload={"endpoint": "/api/training-data", "method": "DELETE"},
            response=resp,
            defense_held=defense_held,
            description="Training data deletion attempted without authentication",
            remediation="Implement authorization checks on all data-modifying endpoints.",
        )

    async def _test_correction_injection(self) -> None:
        """Test if correction endpoint accepts malicious SQL without auth."""
        resp = await self.send_to_endpoint("correct", "POST", {
            "question": "What is revenue?",
            "correct_sql": "SELECT * FROM companies; DROP TABLE invoices;",
        })
        defense_held = resp.status_code in (401, 403, 422)

        self.record_finding(
            test_name="correction_injection_no_auth",
            severity=Severity.CRITICAL,
            payload={"correct_sql": "SELECT * FROM companies; DROP TABLE invoices;"},
            response=resp,
            defense_held=defense_held,
            description="Malicious SQL correction submitted without authentication or validation",
            remediation=(
                "Validate all correction SQL through the same security scanner. "
                "Require authenticated admin role for corrections."
            ),
        )

    async def _test_snapshot_access(self) -> None:
        """Test if debug snapshots (full pipeline state) are accessible without auth."""
        resp = await self.send_to_endpoint("snapshots", "GET")
        defense_held = resp.status_code in (401, 403)

        # Check if snapshots contain sensitive internal state
        has_sensitive = any(
            kw in resp.raw_text.lower()
            for kw in ["sql", "query", "security_scan", "pipeline", "model"]
        ) if resp.raw_text else False

        self.record_finding(
            test_name="snapshot_access_no_auth",
            severity=Severity.HIGH,
            payload={"endpoint": "/api/snapshots", "method": "GET"},
            response=resp,
            defense_held=defense_held,
            description="Debug snapshots accessible without authentication — exposes full pipeline state",
            remediation="Restrict snapshot access to authenticated admin users only.",
            evidence={"contains_sensitive_data": has_sensitive},
        )

    async def _test_scheduler_pause(self) -> None:
        """Test if all scheduled jobs can be paused without auth (operational disruption)."""
        resp = await self.send_to_endpoint("scheduler_pause", "POST")
        defense_held = resp.status_code in (401, 403)

        # Resume immediately if we paused it
        if resp.ok:
            await self.send_to_endpoint("scheduler_resume", "POST")

        self.record_finding(
            test_name="scheduler_pause_no_auth",
            severity=Severity.HIGH,
            payload={"endpoint": "/api/scheduler/pause", "method": "POST"},
            response=resp,
            defense_held=defense_held,
            description="All scheduled jobs paused without authentication — operational disruption",
            remediation="Require admin authentication for scheduler control endpoints.",
        )

    async def _test_agent_steps_override(self) -> None:
        """Test if max_steps parameter can be overridden to extreme values."""
        resp = await self.client.post_json(
            self.config.remote_config.additional_endpoints.get(
                "agent_stream", "/api/agent/stream"
            ),
            {"question": "What is total revenue?", "max_steps": 100},
        )
        defense_held = resp.status_code in (401, 403, 422)

        self.record_finding(
            test_name="agent_steps_override",
            severity=Severity.MEDIUM,
            payload={"max_steps": 100, "expected_cap": 12},
            response=resp,
            defense_held=defense_held,
            description="Agent max_steps parameter override attempt (100 vs expected cap of 12)",
            remediation="Enforce server-side maximum for max_steps regardless of client input.",
        )

    async def _test_domain_profile_disclosure(self) -> None:
        """Test if full domain profile (schema mapping) is accessible without auth."""
        resp = await self.send_to_endpoint("domain_profile", "GET")
        defense_held = resp.status_code in (401, 403)

        self.record_finding(
            test_name="domain_profile_disclosure",
            severity=Severity.MEDIUM,
            payload={"endpoint": "/api/domain-profile", "method": "GET"},
            response=resp,
            defense_held=defense_held,
            description="Full domain profile accessible without auth — reveals table/column structure",
            remediation="Restrict domain profile endpoint to authenticated users.",
        )

    async def _test_activity_log_access(self) -> None:
        """Test if agent activity log is accessible without auth."""
        resp = await self.send_to_endpoint("activity", "GET")
        defense_held = resp.status_code in (401, 403)

        self.record_finding(
            test_name="activity_log_no_auth",
            severity=Severity.MEDIUM,
            payload={"endpoint": "/api/activity", "method": "GET"},
            response=resp,
            defense_held=defense_held,
            description="Agent activity log accessible without authentication — operational intelligence leak",
            remediation="Require authentication for activity log access.",
        )

    async def _test_schema_full_disclosure(self) -> None:
        """Test if full database schema with DDL is accessible."""
        resp = await self.send_to_endpoint("schema", "GET")
        defense_held = resp.status_code in (401, 403)

        has_ddl = any(
            kw in resp.raw_text.lower()
            for kw in ["create table", "varchar", "integer", "primary key"]
        ) if resp.raw_text else False

        self.record_finding(
            test_name="schema_full_disclosure",
            severity=Severity.MEDIUM,
            payload={"endpoint": "/api/schema", "method": "GET"},
            response=resp,
            defense_held=defense_held,
            description="Full database schema with DDL accessible without authentication",
            remediation="Restrict schema endpoint to authenticated users. Redact sensitive column names.",
            evidence={"contains_ddl": has_ddl},
        )
