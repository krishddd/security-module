"""Redactor scrubs registered secrets and well-known token shapes."""

from core.redaction import GLOBAL_REDACTOR, Redactor


def test_registered_secret_is_masked() -> None:
    r = Redactor()
    r.register("super-secret-token-abc123")
    out = r.scrub({"headers": {"Authorization": "Bearer super-secret-token-abc123"}})
    assert "super-secret-token" not in out["headers"]["Authorization"]


def test_jwt_pattern_scrubbed() -> None:
    r = Redactor()
    jwt = "eyJhbGciOi.payload-part-data.signature-bytes_here"
    assert "REDACTED" in r.scrub(f"token={jwt}")


def test_sensitive_header_value_masked() -> None:
    r = Redactor()
    out = r.scrub_headers({"Authorization": "Bearer abc", "X-Trace-Id": "ok"})
    assert "abc" not in out["Authorization"]
    assert out["X-Trace-Id"] == "ok"


def test_short_secrets_ignored() -> None:
    r = Redactor()
    r.register("abc")  # too short, must not turn into a wildcard
    assert r.scrub("the abc of it") == "the abc of it"


def test_global_singleton_exists() -> None:
    assert GLOBAL_REDACTOR is not None
