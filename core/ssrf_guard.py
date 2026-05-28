"""SSRF guard for user-supplied URLs (OpenAPI specs, agent base URLs).

The scanner accepts arbitrary URLs from the user. Without guarding, a
malicious or confused operator could point it at cloud metadata services,
internal admin panels, or other RFC1918 hosts. We resolve URLs to IPs and
match against blocked ranges at the network layer (string-matching the
hostname is not sufficient — DNS rebinding bypasses it).

Bypass with ``allow_internal=True`` when explicitly testing localhost.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# IPv4 + IPv6 ranges that must never be reached without --allow-internal.
_BLOCKED_RANGES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),     # link-local + cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),            # ULA (covers fd00::/8)
    ipaddress.ip_network("fe80::/10"),           # link-local v6
    ipaddress.ip_network("::ffff:0:0/96"),       # v4-mapped v6
]


class SSRFBlockedError(ValueError):
    """Raised when a URL resolves to a blocked address."""


def is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # un-parseable -> fail closed
    return any(ip in net for net in _BLOCKED_RANGES)


def resolve_host(host: str) -> list[str]:
    """Return all A/AAAA records for a hostname. Empty list on resolution
    failure (caller decides how to treat that)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return list({i[4][0] for i in infos})


def assert_url_safe(url: str, *, allow_internal: bool = False) -> None:
    """Raise ``SSRFBlockedError`` if ``url`` resolves to a blocked address.

    When ``allow_internal`` is True, the check becomes a no-op — required for
    localhost / lab testing. Callers must surface this decision in scan logs
    so it's auditable.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"unsupported URL scheme: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise SSRFBlockedError(f"URL has no hostname: {url!r}")

    if allow_internal:
        return

    # Hostname might itself be an IP literal.
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        ips = resolve_host(host)

    if not ips:
        raise SSRFBlockedError(f"could not resolve host {host!r}")

    blocked = [ip for ip in ips if is_blocked_ip(ip)]
    if blocked:
        raise SSRFBlockedError(
            f"host {host!r} resolves to blocked address(es) {blocked}; "
            f"use --allow-internal to override"
        )
