"""Rewrite network_pipeline/api/targets.json with clean URLs.

Bypasses any markdown-rendering chain (clipboard, terminal, IDE) that
would otherwise re-mangle URLs. Run from Security_module/ root:

    python fix_targets.py

Verifies the written bytes contain no markdown-link patterns and prints
the parsed values for spot-check.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


TARGETS = {
    "$schema": "network_pipeline.api.targets/v1",
    "description": "Curated list of public targets that EXPLICITLY authorise security testing.",
    "targets": [
        {
            "id": "vulnweb-php",
            "name": "Acunetix testphp.vulnweb.com (PHP)",
            "target": "http://testphp.vulnweb.com",
            "in_scope": ["domain:testphp.vulnweb.com"],
            "description": "Acunetix public PHP/MySQL test target.",
            "owner": "Acunetix / Invicti",
            "authorisation": "Public test target.",
            "auth_required": False,
            "default_flags": {
                "playbook": "owasp_top10",
                "c2_profile": "balanced",
                "max_iterations": 60,
                "deep_mode": True,
                "rate_caps": {
                    "content_discovery": 4.0,
                    "sqli_scan": 2.0,
                    "sqlmap_dispatch": 0.5,
                    "xss_scan": 2.0,
                    "web_audit": 2.0,
                    "http_probe": 4.0,
                    "parameter_mining": 2.0,
                    "web_crawler": 4.0,
                    "bola_scan": 2.0,
                    "mass_assignment": 2.0,
                    "openapi_scan": 2.0,
                    "graphql_scan": 2.0,
                },
            },
            "expected_findings": ["SQLi", "XSS", "LFI", "info disclosure"],
        },
        {
            "id": "vulnweb-aspnet",
            "name": "Acunetix testaspnet.vulnweb.com (ASP.NET)",
            "target": "http://testaspnet.vulnweb.com",
            "in_scope": ["domain:testaspnet.vulnweb.com"],
            "description": "ASP.NET variant of vulnweb.",
            "owner": "Acunetix / Invicti",
            "authorisation": "Public test target.",
            "auth_required": False,
            "default_flags": {
                "playbook": "owasp_top10",
                "c2_profile": "balanced",
                "max_iterations": 40,
                "deep_mode": True,
                "rate_caps": {
                    "content_discovery": 2.0,
                    "xss_scan": 1.0,
                    "web_audit": 1.0,
                    "http_probe": 2.0,
                    "cve_check": 1.0,
                },
            },
            "expected_findings": ["XSS", "info disclosure"],
        },
        {
            "id": "vulnweb-asp",
            "name": "Acunetix testasp.vulnweb.com (Classic ASP)",
            "target": "http://testasp.vulnweb.com",
            "in_scope": ["domain:testasp.vulnweb.com"],
            "description": "Classic ASP variant.",
            "owner": "Acunetix / Invicti",
            "authorisation": "Public test target.",
            "auth_required": False,
            "default_flags": {
                "playbook": "owasp_top10",
                "c2_profile": "balanced",
                "max_iterations": 40,
                "deep_mode": True,
                "rate_caps": {
                    "sqli_scan": 1.0,
                    "sqlmap_dispatch": 0.5,
                    "auth_audit": 1.0,
                    "web_audit": 1.0,
                    "http_probe": 2.0,
                },
            },
            "expected_findings": ["SQLi", "auth bypass"],
        },
        {
            "id": "vulnweb-html5",
            "name": "Acunetix testhtml5.vulnweb.com (HTML5/JS)",
            "target": "http://testhtml5.vulnweb.com",
            "in_scope": ["domain:testhtml5.vulnweb.com"],
            "description": "HTML5 plus heavy JS app.",
            "owner": "Acunetix / Invicti",
            "authorisation": "Public test target.",
            "auth_required": False,
            "default_flags": {
                "playbook": "owasp_top10",
                "c2_profile": "balanced",
                "max_iterations": 40,
                "deep_mode": True,
                "rate_caps": {
                    "content_discovery": 2.0,
                    "xss_scan": 1.0,
                    "js_endpoints": 2.0,
                    "parameter_mining": 1.0,
                    "web_audit": 1.0,
                },
            },
            "expected_findings": ["DOM XSS", "exposed JS endpoints"],
        },
        {
            "id": "altoro-mutual",
            "name": "IBM AltoroJ Banking Demo",
            "target": "https://demo.testfire.net",
            "in_scope": ["domain:demo.testfire.net"],
            "description": "IBM intentionally-vulnerable Java banking demo. Creds: jsmith / Demo1234.",
            "owner": "IBM",
            "authorisation": "Public test target.",
            "auth_required": True,
            "auth_hint": "Login as jsmith/Demo1234, copy JSESSIONID from DevTools.",
            "default_flags": {
                "playbook": "owasp_top10",
                "c2_profile": "balanced",
                "max_iterations": 80,
                "deep_mode": True,
                "rate_caps": {
                    "content_discovery": 2.0,
                    "sqli_scan": 1.0,
                    "sqlmap_dispatch": 0.5,
                    "xss_scan": 1.0,
                    "auth_audit": 1.0,
                    "jwt_scan": 1.0,
                    "web_audit": 1.0,
                    "http_probe": 2.0,
                },
            },
            "expected_findings": [
                "SQLi in login",
                "XSS in search",
                "IDOR on /bank/transfer",
                "admin panel exposure",
            ],
        },
        {
            "id": "hack-yourself-first",
            "name": "Pluralsight Hack Yourself First",
            "target": "https://hack-yourself-first.com",
            "in_scope": ["domain:hack-yourself-first.com"],
            "description": "Pluralsight intentionally-vulnerable training app.",
            "owner": "Pluralsight",
            "authorisation": "Public training target.",
            "auth_required": False,
            "default_flags": {
                "playbook": "owasp_top10",
                "c2_profile": "balanced",
                "max_iterations": 40,
                "deep_mode": True,
                "rate_caps": {
                    "content_discovery": 2.0,
                    "xss_scan": 1.0,
                    "auth_audit": 1.0,
                    "web_audit": 1.0,
                    "http_probe": 2.0,
                    "cve_check": 1.0,
                },
            },
            "expected_findings": ["XSS", "weak auth", "info disclosure"],
        },
        {
            "id": "scanme-nmap",
            "name": "Nmap project scanme.nmap.org",
            "target": "http://scanme.nmap.org",
            "in_scope": ["domain:scanme.nmap.org"],
            "description": "Nmap authorised port-scan target. Passive plus nmap only.",
            "owner": "Nmap project",
            "authorisation": "Public scan target.",
            "auth_required": False,
            "scope_note": "passive + nmap only",
            "allowed_scanners": [
                "dns_scan",
                "whois_lookup",
                "subdomain_enum",
                "port_scan",
                "tls_audit",
                "http_probe",
            ],
            "default_flags": {
                "playbook": "mitre_discovery",
                "c2_profile": "stealth",
                "max_iterations": 12,
                "rate_caps": {
                    "port_scan": 0.2,
                    "http_probe": 0.2,
                    "dns_scan": 1.0,
                },
            },
            "expected_findings": ["open ports", "service banners"],
        },
    ],
}


def main() -> int:
    dst = Path("network_pipeline") / "api" / "targets.json"
    if not dst.parent.exists():
        print(
            f"error: {dst.parent} not found. Run from Security_module root.",
            file=sys.stderr,
        )
        return 2

    text = json.dumps(TARGETS, indent=2)
    dst.write_text(text, encoding="utf-8")

    raw = dst.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    print(f"wrote {dst.resolve()}")
    print(f"  size: {len(raw)} bytes")
    print(f"  sha256: {sha}")

    bad_patterns = [
        b"[testphp",
        b"[testaspnet",
        b"[testasp.vuln",
        b"[testhtml5",
        b"[demo.testfire",
        b"[hack-yourself",
        b"[scanme.nmap",
        b"](http://",
    ]
    contamination = [p.decode() for p in bad_patterns if p in raw]
    if contamination:
        print(f"FAIL: markdown contamination detected: {contamination}")
        return 1
    print("verify: zero markdown-link patterns in raw bytes")

    with open(dst, encoding="utf-8") as f:
        parsed = json.load(f)
    print(f"verify: parsed {len(parsed['targets'])} targets")
    for t in parsed["targets"]:
        print(f"  {t['id']:22s}  target={t['target']}  in_scope={t['in_scope']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
