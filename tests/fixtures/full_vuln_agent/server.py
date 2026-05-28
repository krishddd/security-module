"""Spawn FullVulnAgent on a fixed port (default 9200) for the demo.

Manual launch:
    python -m tests.fixtures.full_vuln_agent.server --port 9200
"""

from __future__ import annotations

import argparse
import contextlib
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator

import httpx


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def full_vuln_agent_running(port: int | None = None, *, startup_timeout_s: float = 30.0) -> Iterator[str]:
    chosen_port = port or _free_port()
    project_root = Path(__file__).resolve().parents[3]

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn",
         "tests.fixtures.full_vuln_agent.app:app",
         "--host", "127.0.0.1", "--port", str(chosen_port),
         "--log-level", "warning"],
        cwd=str(project_root),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    base_url = f"http://127.0.0.1:{chosen_port}"
    try:
        deadline = time.time() + startup_timeout_s
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"FullVulnAgent exited during startup (rc={proc.returncode})")
            try:
                r = httpx.get(f"{base_url}/api/health", timeout=0.5)
                if r.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            proc.terminate()
            raise RuntimeError(f"FullVulnAgent did not become healthy within {startup_timeout_s}s")
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9200)
    args = ap.parse_args()
    with full_vuln_agent_running(args.port) as base_url:
        print(f"FullVulnAgent running at {base_url} (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\nshutting down")


if __name__ == "__main__":
    _main()
