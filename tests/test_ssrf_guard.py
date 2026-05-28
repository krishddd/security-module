"""SSRF guard blocks RFC1918, loopback, link-local, and IPv6 variants."""

import pytest

from core.ssrf_guard import SSRFBlockedError, assert_url_safe, is_blocked_ip


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.42.1",
        "192.168.1.1",
        "169.254.169.254",   # cloud metadata
        "100.64.0.1",         # CGNAT
        "::1",
        "fd12::1",            # ULA
        "fe80::1",
    ],
)
def test_blocked_ips(ip: str) -> None:
    assert is_blocked_ip(ip) is True


def test_public_ip_allowed() -> None:
    assert is_blocked_ip("8.8.8.8") is False


def test_localhost_url_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        assert_url_safe("http://127.0.0.1/openapi.json")


def test_metadata_service_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        assert_url_safe("http://169.254.169.254/latest/meta-data/")


def test_allow_internal_bypass() -> None:
    # No exception when explicitly allowed.
    assert_url_safe("http://127.0.0.1:8080/openapi.json", allow_internal=True)


def test_unknown_scheme_blocked() -> None:
    with pytest.raises(SSRFBlockedError):
        assert_url_safe("file:///etc/passwd")
