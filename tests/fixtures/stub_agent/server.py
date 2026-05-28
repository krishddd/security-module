"""Spin up the stub agent on a random port in a subprocess.

Used by ``tests/conftest.py`` as a pytest session fixture. Kept as a
separate module so it can also be launched manually:

    python -m tests.fixtures.stub_agent.server --port 9100
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
def stub_agent_running(port: int | None = None, *, startup_timeout_s: float = 90.0) -> Iterator[str]:
    """Context manager that yields the stub agent's base URL."""
    chosen_port = port or _free_port()
    project_root = Path(__file__).resolve().parents[3]  # Security_module/

    # DEVNULL on stdout/stderr to avoid the Windows pipe-buffer deadlock when
    # uvicorn's reload-watcher or our own logging produces enough output to
    # fill the OS pipe before the parent reads.
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "tests.fixtures.stub_agent.app:app",
            "--host", "127.0.0.1",
            "--port", str(chosen_port),
            "--log-level", "warning",
        ],
        cwd=str(project_root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base_url = f"http://127.0.0.1:{chosen_port}"
    try:
        deadline = time.time() + startup_timeout_s
        last_err: Exception | None = None
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"stub agent exited during startup (rc={proc.returncode}). "
                    f"Re-run manually: python -m uvicorn tests.fixtures.stub_agent.app:app --port {chosen_port}"
                )
            try:
                r = httpx.get(f"{base_url}/healthz", timeout=0.5)
                if r.status_code == 200:
                    break
            except httpx.HTTPError as e:
                last_err = e
            time.sleep(0.2)
        else:
            proc.terminate()
            raise RuntimeError(
                f"stub agent did not become healthy within {startup_timeout_s}s "
                f"(last error: {last_err!r})"
            )
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args()
    with stub_agent_running(args.port) as base_url:
        print(f"stub agent running at {base_url} (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\nshutting down")


if __name__ == "__main__":
    _main()
