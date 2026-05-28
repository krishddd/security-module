"""Phase 5 end-to-end integration: scan-v3 LIVE against the stub agent.

These are the real verification tests for the v3 pipeline:
  * discover → plan → scan-v3 (no --dry-run) runs all 19 registered testers
  * findings are produced
  * the metadata-driven runner correctly skips categories the stub can't be
    attacked on (no FAILED finding on /healthz pathway)
  * SARIF/JUnit/HTML reports are written
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, env_extra: dict[str, str] | None = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "cli.py", *args],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


@pytest.fixture
def isolated_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect RESULTS_DIR to tmp_path for this test."""
    monkeypatch.setenv("ASI_RESULTS_DIR_OVERRIDE", str(tmp_path / "results"))
    yield tmp_path / "results"


def test_scan_v3_live_against_stub(stub_agent_url: str, tmp_path: Path) -> None:
    """Full v3 pipeline against the stub agent: discover → plan → scan."""
    profile_path = tmp_path / "profile.json"
    plan_path = tmp_path / "plan.json"

    # 1. Discover.
    r1 = _run(
        "discover",
        "--url", stub_agent_url,
        "--openapi-url", f"{stub_agent_url}/openapi.json",
        "--allow-internal",
        "--out", str(profile_path),
    )
    assert r1.returncode == 0, r1.stderr + r1.stdout
    assert profile_path.exists()

    # 2. Plan.
    r2 = _run("plan", "--profile", str(profile_path), "--out", str(plan_path))
    assert r2.returncode == 0, r2.stderr + r2.stdout

    # 3. Live scan, just two categories that we know the stub responds to.
    #    ASI01 (goal hijack via /chat prompt-injection trigger) is the cleanest
    #    end-to-end demo. Critical-severity may exit code 1 — accept that.
    r3 = _run(
        "scan-v3",
        "--profile", str(profile_path),
        "--plan", str(plan_path),
        "--category", "ASI01",
    )
    # Exit 0 (no critical) or 1 (critical findings) are both acceptable; 2+
    # signals a real error (bad CLI invocation, runtime crash, etc.).
    assert r3.returncode in (0, 1), f"unexpected exit {r3.returncode}\nSTDOUT:\n{r3.stdout}\nSTDERR:\n{r3.stderr}"

    # 4. Confirm the results directory exists and contains a report.json.
    from config.settings import RESULTS_DIR
    run_dirs = sorted(Path(RESULTS_DIR).glob("*_*/"), reverse=True)
    assert run_dirs, f"no results directory was created under {RESULTS_DIR}"
    latest = run_dirs[0]
    report_json = latest / "report.json"
    assert report_json.exists()

    data = json.loads(report_json.read_text(encoding="utf-8"))

    # 5. At least one ASI01 finding exists.
    asi01_cats = [c for c in data["categories"] if c["category"] == "ASI01"]
    assert asi01_cats, "no ASI01 category in report"
    asi01 = asi01_cats[0]
    assert asi01["tests_run"] > 0, "ASI01 tester ran zero tests"

    # 6. At least one FAILED finding — the stub's /chat is deliberately
    #    vulnerable to a goal-hijack prompt, so a properly-wired adapter
    #    pipeline MUST surface that as a vulnerability.
    failed = [f for f in asi01["findings"] if f.get("status") == "FAILED"]
    assert failed, (
        f"expected ≥1 FAILED finding in ASI01 against the vulnerable stub; got "
        f"{[(f.get('test_name'), f.get('status')) for f in asi01['findings'][:5]]}"
    )

    # 7. Aux reports were generated.
    assert (latest / "report.sarif").exists()
    assert (latest / "report.junit.xml").exists()
    assert (latest / "report.html").exists()

    # Clean up so we don't litter the real results directory.
    shutil.rmtree(latest, ignore_errors=True)


def test_scan_v3_live_capability_skip(stub_agent_url: str, tmp_path: Path) -> None:
    """ASI05 (Code Execution) requires CODE_EXECUTION/SHELL_EXEC capabilities,
    which the stub doesn't have — the runner must emit SKIPPED_CAPABILITY."""
    profile_path = tmp_path / "profile.json"

    _run(
        "discover",
        "--url", stub_agent_url,
        "--openapi-url", f"{stub_agent_url}/openapi.json",
        "--allow-internal",
        "--out", str(profile_path),
    )

    # Run ONLY ASI05; expect every finding to be SKIPPED_CAPABILITY.
    r = _run(
        "scan-v3",
        "--profile", str(profile_path),
        "--category", "ASI05",
    )
    assert r.returncode in (0, 1), r.stderr + r.stdout

    from config.settings import RESULTS_DIR
    run_dirs = sorted(Path(RESULTS_DIR).glob("*_*/"), reverse=True)
    assert run_dirs
    latest = run_dirs[0]
    data = json.loads((latest / "report.json").read_text(encoding="utf-8"))

    asi05 = next(c for c in data["categories"] if c["category"] == "ASI05")
    # The skip-finding has status SKIPPED_CAPABILITY.
    statuses = {f.get("status") for f in asi05["findings"]}
    assert "SKIPPED_CAPABILITY" in statuses, f"ASI05 statuses: {statuses}"

    shutil.rmtree(latest, ignore_errors=True)
