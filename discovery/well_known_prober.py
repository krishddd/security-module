"""Heuristic fallback when no OpenAPI URL is supplied.

Probes a list of well-known locations on the agent's base URL and returns
the first that looks like a spec. If nothing is found, the caller falls
back to manual manifest entry.
"""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from core.ssrf_guard import assert_url_safe

_PROBE_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/v1/openapi.json",
    "/api/openapi.json",
    "/.well-known/ai-plugin.json",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
]


def probe_well_known(
    base_url: str,
    *,
    allow_internal: bool = False,
    timeout_s: float = 5.0,
) -> str | None:
    """Return the URL of the first spec-looking document found, else None."""
    assert_url_safe(base_url, allow_internal=allow_internal)
    with httpx.Client(timeout=timeout_s, follow_redirects=False) as client:
        for path in _PROBE_PATHS:
            candidate = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = client.get(candidate)
            except httpx.HTTPError:
                continue
            if resp.status_code != 200:
                continue
            ctype = resp.headers.get("content-type", "").lower()
            if "json" not in ctype and not candidate.endswith(".json"):
                continue
            # Sanity: top-level looks like an OpenAPI doc.
            try:
                doc = resp.json()
            except ValueError:
                continue
            if isinstance(doc, dict) and ("paths" in doc or "openapi" in doc or "swagger" in doc):
                return candidate
    return None
