"""Unit tests for resolver.py (CIDR matching, domain rules, PSL, private IPs, cache)."""

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
    """Private, loopback, link-local, and multicast IPs get translated labels without calling rDNS."""
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
        assert calls.count("93.184.216.34") == 1

        # Failing lookup on a global IP gets negatively cached (not re-queried)
        assert resolver.resolve("93.184.216.99", wait_timeout=1.0) == "93.184.216.99"
        assert resolver.resolve("93.184.216.99") == "93.184.216.99"
        assert calls.count("93.184.216.99") == 1
        assert resolver.metrics().negative_entries == 1
    finally:
        resolver.shutdown()
