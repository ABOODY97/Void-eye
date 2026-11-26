"""Unit tests for resolver.py (CIDR, PSL, private/CGNAT IPs, spoofing defense, cache)."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import time

import pytest

from i18n import set_language
from resolver import (
    Resolver,
    clean_hostname,
    extract_registered_domain,
    load_known_database,
    sanitize_csv_field,
    sanitize_network_text,
)


@pytest.fixture(autouse=True)
def _force_english_locale() -> None:
    """Ensure deterministic English labels across all resolver tests."""
    set_language("en")


def test_cidr_matching_ipv4_ipv6_and_specificity(tmp_path: Path) -> None:
    """Resolver matches exact CIDR blocks (not naive 2-octet prefixes) with longest-prefix priority."""
    db_file = tmp_path / "known_ips.json"
    db_file.write_text(
        json.dumps(
            {
                "known_ips": {"8.8.8.8": "Google DNS"},
                "known_ranges": {
                    "192.30.252.0/22": "GitHub",
                    "104.16.0.0/13": "Cloudflare",
                    "104.16.100.0/24": "Cloudflare Special",
                    "2606:4700::/32": "Cloudflare IPv6",
                },
                "domain_keywords": {},
            }
        ),
        encoding="utf-8",
    )

    resolver = Resolver(db_path=db_file, enable_async_rdns=False)

    # Exact IP
    assert resolver.resolve("8.8.8.8") == "Google DNS"

    # Inside 192.30.252.0/22 -> GitHub, outside /22 (same first two octets!) -> raw IP
    assert resolver.resolve("192.30.252.129") == "GitHub"
    assert resolver.resolve("192.30.10.5") == "192.30.10.5"

    # Longest prefix match (/24 beats /13)
    assert resolver.resolve("104.16.100.42") == "Cloudflare Special"
    assert resolver.resolve("104.20.1.1") == "Cloudflare"

    # IPv6 CIDR match
    assert resolver.resolve("2606:4700:4700::64") == "Cloudflare IPv6"


@pytest.mark.parametrize(
    ("hostname", "expected_registered"),
    [
        ("sub.example.com", "example.com"),
        ("www.example.com.", "example.com"),
        ("news.bbc.co.uk", "bbc.co.uk"),
        ("portal.haber.com.tr", "haber.com.tr"),
        ("api.gov.sa", "api.gov.sa"),
        ("shop.store.com.au", "store.com.au"),
        ("localhost", "localhost"),
    ],
)
def test_extract_registered_domain_multi_part_suffixes(
    hostname: str, expected_registered: str
) -> None:
    """Multi-part ccTLD public suffixes preserve the registrable label."""
    assert extract_registered_domain(hostname) == expected_registered


def test_domain_keyword_matching_avoids_substring_false_positives() -> None:
    """Whole-label & exact-domain matching prevents 'live', 'snap', 'redd', 'zoom' false positives."""
    exact_domains = {
        "live.com": "Microsoft Live",
        "redd.it": "Reddit",
        "zoom.us": "Zoom",
        "snap.com": "Snapchat",
    }
    label_keywords = {
        "google": "Google",
        "snapchat": "Snapchat",
        "reddit": "Reddit",
        "apple": "Apple",
    }

    # Legitimate matches (including multi-part public suffixes)
    assert clean_hostname("login.live.com", exact_domains, label_keywords) == "Microsoft Live"
    assert clean_hostname("i.redd.it", exact_domains, label_keywords) == "Reddit"
    assert clean_hostname("us04web.zoom.us", exact_domains, label_keywords) == "Zoom"
    assert clean_hostname("www.google.com.tr", exact_domains, label_keywords) == "Google"
    assert clean_hostname("mail.google.co.uk", exact_domains, label_keywords) == "Google"
    assert clean_hostname("app.snapchat.com", exact_domains, label_keywords) == "Snapchat"

    # Former false positives must NOT match brand names
    assert clean_hostname("cdn.deliver.com", exact_domains, label_keywords) == "deliver.com"
    assert clean_hostname("live.bbc.co.uk", exact_domains, label_keywords) == "bbc.co.uk"
    assert clean_hostname("pkg.synapse.org", exact_domains, label_keywords) == "synapse.org"
    assert clean_hostname("snap.canonical.com", exact_domains, label_keywords) == "canonical.com"
    assert clean_hostname("shop.shredder.com", exact_domains, label_keywords) == "shredder.com"
    assert clean_hostname("app.zoominfo.com", exact_domains, label_keywords) == "zoominfo.com"
    assert clean_hostname("juice.pineapple.com", exact_domains, label_keywords) == "pineapple.com"


def test_private_loopback_and_link_local_never_trigger_rdns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Private, CGNAT, loopback, link-local, and multicast IPs get translated labels without rDNS."""
    db_file = tmp_path / "empty.json"
    db_file.write_text("{}", encoding="utf-8")

    def _forbidden_rdns(ip: str) -> tuple[str, list[str], list[str]]:
        raise AssertionError(f"Reverse DNS must not be called for non-global IP {ip}")

    monkeypatch.setattr(socket, "gethostbyaddr", _forbidden_rdns)
    resolver = Resolver(db_path=db_file, enable_async_rdns=True)
    try:
        assert resolver.resolve("192.168.1.25") == "192.168.1.25 (LAN)"
        assert resolver.resolve("10.0.0.1") == "10.0.0.1 (LAN)"
        assert resolver.resolve("172.16.5.4") == "172.16.5.4 (LAN)"
        assert resolver.resolve("127.0.0.1") == "127.0.0.1 (Localhost)"
        assert resolver.resolve("::1") == "::1 (Localhost)"
        assert resolver.resolve("169.254.10.20") == "169.254.10.20 (Link-Local)"
        assert resolver.resolve("fe80::1") == "fe80::1 (Link-Local)"
        assert resolver.resolve("224.0.0.251") == "224.0.0.251 (Multicast)"
    finally:
        resolver.shutdown()


def test_corrupt_or_missing_known_ips_json_handled_gracefully(tmp_path: Path) -> None:
    """Missing or malformed JSON degrades cleanly to an empty database without raising."""
    missing_db = load_known_database(tmp_path / "does_not_exist.json")
    assert missing_db.known_ips == {}
    assert missing_db.ipv4_ranges == []

    corrupt_path = tmp_path / "corrupt.json"
    corrupt_path.write_text("{not valid json!!", encoding="utf-8")
    corrupt_db = load_known_database(corrupt_path)
    assert corrupt_db.known_ips == {}

    partial_path = tmp_path / "partial.json"
    partial_path.write_text(
        json.dumps(
            {
                "known_ips": {"not-an-ip": "Bad", "1.1.1.1": "Cloudflare DNS"},
                "known_ranges": {"999.999.0.0/16": "Bad CIDR", "9.9.9.0/24": "Quad9"},
            }
        ),
        encoding="utf-8",
    )
    partial_db = load_known_database(partial_path)
    assert partial_db.known_ips == {"1.1.1.1": "Cloudflare DNS"}
    assert len(partial_db.ipv4_ranges) == 1


def test_async_rdns_and_negative_caching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First lookup returns raw IP immediately; background rDNS populates positive & negative cache."""
    db_file = tmp_path / "empty.json"
    db_file.write_text("{}", encoding="utf-8")

    calls: list[str] = []

    def _fake_rdns(ip: str) -> tuple[str, list[str], list[str]]:
        calls.append(ip)
        time.sleep(0.03)
        if ip == "93.184.216.34":
            return ("edge.example.co.uk", [], [ip])
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(socket, "gethostbyaddr", _fake_rdns)
    resolver = Resolver(db_path=db_file, max_cache_size=16, enable_async_rdns=True)
    try:
        # Non-blocking call returns raw IP immediately
        assert resolver.resolve("93.184.216.34") == "93.184.216.34"

        # Waiting briefly resolves to cleaned registered domain from cache
        assert resolver.resolve("93.184.216.34", wait_timeout=1.0) == "example.co.uk"
        assert resolver.resolve("93.184.216.34") == "example.co.uk"
        detailed = resolver.resolve_detailed("93.184.216.34")
        assert detailed.source == "rdns"
        assert detailed.display_name == "~example.co.uk"
        assert calls.count("93.184.216.34") == 1

        # Failing lookup on a global IP gets negatively cached (not re-queried)
        assert resolver.resolve("93.184.216.99", wait_timeout=1.0) == "93.184.216.99"
        assert resolver.resolve("93.184.216.99") == "93.184.216.99"
        assert calls.count("93.184.216.99") == 1
        assert resolver.metrics().negative_entries == 1
    finally:
        resolver.shutdown()


def test_cgnat_range_labeled_distinctly_from_lan(tmp_path: Path) -> None:
    """RFC 6598 100.64.0.0/10 addresses are labeled CGNAT rather than LAN."""
    db_file = tmp_path / "empty.json"
    db_file.write_text("{}", encoding="utf-8")
    resolver = Resolver(db_path=db_file, enable_async_rdns=False)

    assert resolver.resolve("100.64.0.1") == "100.64.0.1 (CGNAT)"
    assert resolver.resolve("100.100.100.100") == "100.100.100.100 (CGNAT)"
    assert resolver.resolve("100.127.255.254") == "100.127.255.254 (CGNAT)"
    # 100.128.0.1 is outside 100.64.0.0/10 (public global space)
    assert resolver.resolve("100.128.0.1") == "100.128.0.1"


def test_sanitize_network_text_blocks_escape_and_control_sequences() -> None:
    """ANSI escapes, C0/C1 controls, BiDi overrides, and overlong strings are neutralized."""
    malicious = "evil\x1b[31m.example\x07\r\n\u202ecom"
    cleaned = sanitize_network_text(malicious)
    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "\u202e" not in cleaned
    assert cleaned == "evil?[31m.example????com"

    overlong = "a" * 400
    assert len(sanitize_network_text(overlong)) == 253
    assert sanitize_network_text(b"sub.\x1b]2;pwn\x07example.org") == "sub.?]2;pwn?example.org"


def test_csv_formula_injection_sanitization() -> None:
    """Spreadsheet formula prefixes (=, +, -, @) are escaped with a leading quote."""
    assert sanitize_csv_field("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_field("+SUM(1,2)") == "'+SUM(1,2)"
    assert sanitize_csv_field("-2+3") == "'-2+3"
    assert sanitize_csv_field("@IMPORTXML()") == "'@IMPORTXML()"
    assert sanitize_csv_field("safe.example.com") == "safe.example.com"
    assert sanitize_csv_field(443) == 443


def test_dns_label_spoofing_protection_and_cdn_sni_priority(tmp_path: Path) -> None:
    """Unsolicited/mismatched DNS answers are ignored; SNI > DNS > rDNS > CIDR without flapping."""
    db_file = tmp_path / "cdn.json"
    db_file.write_text(
        json.dumps(
            {
                "known_ips": {},
                "known_ranges": {"104.16.0.0/13": "Cloudflare"},
                "domain_keywords": {},
            }
        ),
        encoding="utf-8",
    )
    resolver = Resolver(db_path=db_file, enable_async_rdns=False, max_recent_names=3)
    cdn_ip = "104.16.132.229"

    # Initially matches CIDR (authenticated local DB -> no '~' prefix)
    res0 = resolver.resolve_detailed(cdn_ip)
    assert res0.name == "Cloudflare"
    assert res0.source == "cidr"
    assert res0.display_name == "Cloudflare"

    # 1. Unsolicited DNS response (no prior outbound query) MUST be rejected
    accepted = resolver.learn_dns_response(
        client_ip="192.168.1.10",
        server_ip="8.8.8.8",
        txid=0x1234,
        qname="spoofed.bank.com",
        mappings=[(cdn_ip, "spoofed.bank.com")],
    )
    assert accepted is False
    assert resolver.resolve(cdn_ip) == "Cloudflare"

    # 2. Record genuine outbound query, then test mismatched TXID & wrong server IP
    resolver.record_dns_query("192.168.1.10", "8.8.8.8", 0xBEEF, "portal.acme.org")
    assert (
        resolver.learn_dns_response(
            client_ip="192.168.1.10",
            server_ip="1.1.1.1",  # wrong resolver IP
            txid=0xBEEF,
            qname="portal.acme.org",
            mappings=[(cdn_ip, "portal.acme.org")],
        )
        is False
    )
    assert (
        resolver.learn_dns_response(
            client_ip="192.168.1.10",
            server_ip="8.8.8.8",
            txid=0x0001,  # wrong txid
            qname="portal.acme.org",
            mappings=[(cdn_ip, "portal.acme.org")],
        )
        is False
    )

    # 3. Matching DNS response succeeds and upgrades CIDR -> DNS (marked '~')
    assert (
        resolver.learn_dns_response(
            client_ip="192.168.1.10",
            server_ip="8.8.8.8",
            txid=0xBEEF,
            qname="portal.acme.org",
            mappings=[(cdn_ip, "portal.acme.org")],
        )
        is True
    )
    res_dns = resolver.resolve_detailed(cdn_ip)
    assert res_dns.name == "acme.org"
    assert res_dns.source == "dns"
    assert res_dns.display_name == "~acme.org"

    # Replay of already-consumed TXID is rejected
    assert (
        resolver.learn_dns_response(
            client_ip="192.168.1.10",
            server_ip="8.8.8.8",
            txid=0xBEEF,
            qname="portal.acme.org",
            mappings=[(cdn_ip, "evil.org")],
        )
        is False
    )

    # 4. TLS SNI arrives -> upgrades to SNI; subsequent DNS for shared CDN IP NEVER overwrites SNI
    resolver.learn_sni(cdn_ip, "app1.acme.org")
    assert resolver.resolve_detailed(cdn_ip).name == "app1.acme.org"
    assert resolver.resolve_detailed(cdn_ip).source == "sni"

    resolver.record_dns_query("192.168.1.10", "8.8.8.8", 0x2222, "other-tenant.io")
    assert (
        resolver.learn_dns_response(
            client_ip="192.168.1.10",
            server_ip="8.8.8.8",
            txid=0x2222,
            qname="other-tenant.io",
            mappings=[(cdn_ip, "other-tenant.io")],
        )
        is True
    )
    # Primary name MUST stay the SNI-derived name ("app1.acme.org"), NOT flap to DNS!
    after_other_dns = resolver.resolve_detailed(cdn_ip)
    assert after_other_dns.name == "app1.acme.org"
    assert after_other_dns.source == "sni"
    assert "other-tenant.io" in after_other_dns.recent_names

    # Newer SNI on the same shared IP updates to the most recent SNI while bounding recent_names
    resolver.learn_sni(cdn_ip, "app2.acme.org")
    latest = resolver.resolve_detailed(cdn_ip)
    assert latest.name == "app2.acme.org"
    assert latest.source == "sni"
    assert len(latest.recent_names) <= 3


def test_rdns_timeout_prevents_worker_stall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Slow reverse DNS lookups time out cleanly via Future timeout without hanging workers."""
    db_file = tmp_path / "empty.json"
    db_file.write_text("{}", encoding="utf-8")

    def _stalled_rdns(ip: str) -> tuple[str, list[str], list[str]]:
        time.sleep(2.0)
        return ("never.reached.example", [], [ip])

    monkeypatch.setattr(socket, "gethostbyaddr", _stalled_rdns)
    resolver = Resolver(
        db_path=db_file,
        rdns_workers=1,
        rdns_timeout=0.08,
        enable_async_rdns=True,
    )
    try:
        t0 = time.monotonic()
        result = resolver.resolve("93.184.216.50", wait_timeout=0.5)
        elapsed = time.monotonic() - t0
        assert result == "93.184.216.50"
        assert elapsed < 0.45
        assert resolver.metrics().negative_entries == 1
    finally:
        resolver.shutdown()
