"""End-to-end tests for the v3 CLI: discover → plan → scan --dry-run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke `python cli.py <args>` and return the completed process."""
    return subprocess.run(
        [sys.executable, "cli.py", *args],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_discover_writes_profile(stub_agent_url: str, tmp_path: Path) -> None:
    out = tmp_path / "profile.json"
    res = _run(
        "discover",
        "--url", stub_agent_url,
        "--openapi-url", f"{stub_agent_url}/openapi.json",
        "--allow-internal",
        "--out", str(out),
    )
    assert res.returncode == 0, res.stderr + res.stdout
    assert out.exists()
    profile = json.loads(out.read_text(encoding="utf-8"))
    assert profile["schema_version"] == "3.0"
    paths = {e["path"] for e in profile["endpoints"]}
    assert {"/chat", "/sql_tool", "/file_read", "/healthz"} <= paths


def test_discover_blocks_localhost_without_allow_internal(stub_agent_url: str, tmp_path: Path) -> None:
    res = _run(
        "discover",
        "--url", stub_agent_url,
        "--openapi-url", f"{stub_agent_url}/openapi.json",
        "--out", str(tmp_path / "x.json"),
    )
    assert res.returncode != 0
    combined = (res.stderr + res.stdout).lower()
    assert "blocked" in combined or "ssrf" in combined or "169.254" in combined or "127.0.0.1" in combined


def test_discover_dry_run_makes_no_files(stub_agent_url: str, tmp_path: Path) -> None:
    out = tmp_path / "nope.json"
    res = _run(
        "discover",
        "--url", stub_agent_url,
        "--openapi-url", f"{stub_agent_url}/openapi.json",
        "--allow-internal",
        "--dry-run",
        "--out", str(out),
    )
    assert res.returncode == 0, res.stderr
    assert not out.exists()
    assert "dry-run" in res.stdout.lower() or "dry_run" in res.stdout.lower() or "would fetch" in res.stdout.lower()


def test_plan_then_scan_dry_run(stub_agent_url: str, tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.json"
    plan_path = tmp_path / "plan.json"

    r1 = _run(
        "discover",
        "--url", stub_agent_url,
        "--openapi-url", f"{stub_agent_url}/openapi.json",
        "--allow-internal",
        "--out", str(profile_path),
    )
    assert r1.returncode == 0, r1.stderr + r1.stdout

    r2 = _run("plan", "--profile", str(profile_path), "--out", str(plan_path))
    assert r2.returncode == 0, r2.stderr + r2.stdout
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["schema_version"] == "3.0"
    assert plan["planner"] == "stub"
    # Every category appears in the plan (skip or include).
    from models.enums import RiskCategory
    assert {c["category"] for c in plan["categories"]} == {c.value for c in RiskCategory}

    r3 = _run("scan-v3", "--profile", str(profile_path), "--plan", str(plan_path), "--dry-run")
    assert r3.returncode == 0, r3.stderr + r3.stdout
    out = r3.stdout
    assert "dry-run" in out.lower()
    # At least one ASI category line printed.
    assert "ASI01" in out
    # Cost estimate appears.
    assert "Cost estimate" in out


def test_scan_v3_category_filter_marks_others_skipped(stub_agent_url: str, tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.json"
    _run(
        "discover",
        "--url", stub_agent_url,
        "--openapi-url", f"{stub_agent_url}/openapi.json",
        "--allow-internal",
        "--out", str(profile_path),
    )
    res = _run(
        "scan-v3",
        "--profile", str(profile_path),
        "--dry-run",
        "--category", "ASI02",
        "--category", "EXT10",
    )
    assert res.returncode == 0, res.stderr + res.stdout
    out = res.stdout

    # Filtered categories listed under "skipped" with the right reason.
    assert "SKIPPED_CATEGORY_FILTER" in out
    # The two named categories were not filtered out.
    assert "ASI02" in out
    assert "EXT10" in out


# test_scan_v3_live_mode_refuses_without_adapter removed in Phase 5:
# the Phase-4 guardrail it asserted is now intentionally lifted — scan-v3
# runs a live scan when --dry-run is omitted. End-to-end live coverage
# moved to tests/test_scan_v3_live.py.
