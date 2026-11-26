"""Optional offline-safe utility to refresh known_ranges in known_ips.json.

Fetches official IPv4/IPv6 CIDR prefixes published by:
- Google     : https://www.gstatic.com/ipranges/goog.json
- AWS        : https://ip-ranges.amazonaws.com/ip-ranges.json
- Cloudflare : https://www.cloudflare.com/ips-v4 & https://www.cloudflare.com/ips-v6

Every prefix is validated with Python's ``ipaddress`` module (rejecting default
routes, private/loopback/multicast blocks, and malformed entries) and summarized
with ``ipaddress.collapse_addresses``. If offline or any feed fails, existing
ranges for that provider are preserved without corrupting known_ips.json.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import ipaddress
import json
import logging
from pathlib import Path
import sys
from typing import Any
import urllib.error
import urllib.request

logger = logging.getLogger("update_ranges")

GOOGLE_URL = "https://www.gstatic.com/ipranges/goog.json"
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
CLOUDFLARE_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_V6_URL = "https://www.cloudflare.com/ips-v6"

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "known_ips.json"

MANAGED_LABELS_BY_SOURCE: dict[str, frozenset[str]] = {
    "google": frozenset({"Google"}),
    "aws": frozenset({"Amazon AWS", "Amazon CloudFront"}),
    "cloudflare": frozenset({"Cloudflare"}),
}

_MIN_IPV4_PREFIX = 8
_MIN_IPV6_PREFIX = 16


def validate_public_cidr(
    raw_cidr: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse and validate that *raw_cidr* is a sane public routable prefix."""
    cleaned = raw_cidr.strip()
    if not cleaned:
        return None
    try:
        net = ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        return None

    min_prefix = (
        _MIN_IPV4_PREFIX
        if isinstance(net, ipaddress.IPv4Network)
        else _MIN_IPV6_PREFIX
    )
    if net.prefixlen < min_prefix:
        return None
    if (
        net.is_private
        or net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_unspecified
        or net.is_reserved
    ):
        return None
    return net


def _fetch_text(url: str, timeout: float) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "void-eye-range-updater/2.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw_bytes: bytes = resp.read(32 * 1024 * 1024)
    return raw_bytes.decode("utf-8", errors="strict")


def parse_google_ranges(raw_json: str) -> dict[str, str]:
    """Extract validated Google IPv4/IPv6 CIDRs from goog.json payload."""
    data = json.loads(raw_json)
    if not isinstance(data, dict) or not isinstance(data.get("prefixes"), list):
        raise ValueError("Unexpected schema in Google goog.json")

    results: dict[str, str] = {}
    for entry in data["prefixes"]:
        if not isinstance(entry, dict):
            continue
        cidr = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        if isinstance(cidr, str):
            net = validate_public_cidr(cidr)
            if net is not None:
                results[str(net)] = "Google"
    return results


def parse_aws_ranges(raw_json: str) -> dict[str, str]:
    """Extract and collapse validated AWS & CloudFront CIDRs from ip-ranges.json."""
    data = json.loads(raw_json)
    if not isinstance(data, dict):
        raise ValueError("Unexpected schema in AWS ip-ranges.json")

    v4_by_label: dict[str, list[ipaddress.IPv4Network]] = defaultdict(list)
    v6_by_label: dict[str, list[ipaddress.IPv6Network]] = defaultdict(list)

    for item in data.get("prefixes", []):
        if not isinstance(item, dict):
            continue
        cidr = item.get("ip_prefix")
        service = str(item.get("service", "")).upper()
        if not isinstance(cidr, str):
            continue
        net = validate_public_cidr(cidr)
        if isinstance(net, ipaddress.IPv4Network):
            label = "Amazon CloudFront" if service == "CLOUDFRONT" else "Amazon AWS"
            v4_by_label[label].append(net)

    for item in data.get("ipv6_prefixes", []):
        if not isinstance(item, dict):
            continue
        cidr = item.get("ipv6_prefix")
        service = str(item.get("service", "")).upper()
        if not isinstance(cidr, str):
            continue
        net = validate_public_cidr(cidr)
        if isinstance(net, ipaddress.IPv6Network):
            label = "Amazon CloudFront" if service == "CLOUDFRONT" else "Amazon AWS"
            v6_by_label[label].append(net)

    results: dict[str, str] = {}
    # Assign generic AWS first so more specific CloudFront prefixes take precedence.
    for label in ("Amazon AWS", "Amazon CloudFront"):
        for collapsed4 in ipaddress.collapse_addresses(v4_by_label[label]):
            results[str(collapsed4)] = label
        for collapsed6 in ipaddress.collapse_addresses(v6_by_label[label]):
            results[str(collapsed6)] = label
    return results


def parse_cloudflare_ranges(raw_v4: str, raw_v6: str) -> dict[str, str]:
    """Extract validated Cloudflare CIDRs from plain-text ips-v4 and ips-v6 feeds."""
    results: dict[str, str] = {}
    for line in f"{raw_v4}\n{raw_v6}".splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        net = validate_public_cidr(stripped)
        if net is not None:
            results[str(net)] = "Cloudflare"
    return results


def merge_ranges(
    existing_ranges: dict[str, str],
    fetched_by_source: dict[str, dict[str, str]],
) -> dict[str, str]:
    """Merge refreshed provider CIDRs while preserving untouched/offline providers."""
    refreshed_labels: set[str] = set()
    for src_name, src_map in fetched_by_source.items():
        if src_map:
            refreshed_labels.update(MANAGED_LABELS_BY_SOURCE.get(src_name, frozenset()))

    merged: dict[str, str] = {}
    for cidr, label in existing_ranges.items():
        if label in refreshed_labels:
            continue
        net = validate_public_cidr(cidr)
        if net is not None:
            merged[str(net)] = label

    for src_map in fetched_by_source.values():
        merged.update(src_map)

    return merged


def update_database(
    db_path: Path = DEFAULT_DB_PATH,
    *,
    timeout: float = 10.0,
    offline_dir: Path | None = None,
    dry_run: bool = False,
) -> int:
    """Refresh known_ranges in *db_path*; return 0 even when offline (safe no-op)."""
    if not db_path.is_file():
        logger.error("Database file does not exist: %s", db_path)
        return 1

    try:
        db_obj: dict[str, Any] = json.loads(db_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to read %s: %s", db_path, exc)
        return 1

    existing_ranges = db_obj.get("known_ranges", {})
    if not isinstance(existing_ranges, dict):
        existing_ranges = {}

    fetched: dict[str, dict[str, str]] = {}

    # 1. Google
    try:
        raw_google = (
            (offline_dir / "goog.json").read_text(encoding="utf-8")
            if offline_dir
            else _fetch_text(GOOGLE_URL, timeout)
        )
        fetched["google"] = parse_google_ranges(raw_google)
        logger.info("Loaded %d Google prefixes.", len(fetched["google"]))
    except (OSError, urllib.error.URLError, ValueError, TimeoutError) as exc:
        logger.warning("Skipping Google update (offline or unreachable): %s", exc)

    # 2. AWS
    try:
        raw_aws = (
            (offline_dir / "ip-ranges.json").read_text(encoding="utf-8")
            if offline_dir
            else _fetch_text(AWS_URL, timeout)
        )
        fetched["aws"] = parse_aws_ranges(raw_aws)
        logger.info("Loaded %d collapsed AWS/CloudFront prefixes.", len(fetched["aws"]))
    except (OSError, urllib.error.URLError, ValueError, TimeoutError) as exc:
        logger.warning("Skipping AWS update (offline or unreachable): %s", exc)

    # 3. Cloudflare
    try:
        if offline_dir:
            raw_cf4 = (offline_dir / "ips-v4").read_text(encoding="utf-8")
            raw_cf6 = (offline_dir / "ips-v6").read_text(encoding="utf-8")
        else:
            raw_cf4 = _fetch_text(CLOUDFLARE_V4_URL, timeout)
            raw_cf6 = _fetch_text(CLOUDFLARE_V6_URL, timeout)
        fetched["cloudflare"] = parse_cloudflare_ranges(raw_cf4, raw_cf6)
        logger.info("Loaded %d Cloudflare prefixes.", len(fetched["cloudflare"]))
    except (OSError, urllib.error.URLError, ValueError, TimeoutError) as exc:
        logger.warning("Skipping Cloudflare update (offline or unreachable): %s", exc)

    if not any(fetched.values()):
        logger.warning(
            "No remote feeds were reachable; keeping existing known_ips.json intact."
        )
        return 0

    db_obj["known_ranges"] = merge_ranges(existing_ranges, fetched)
    logger.info("Total validated CIDR ranges after merge: %d", len(db_obj["known_ranges"]))

    if dry_run:
        logger.info("Dry-run enabled; skipping write to %s.", db_path)
        return 0

    try:
        tmp_path = db_path.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(db_obj, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        tmp_path.replace(db_path)
        logger.info("Updated %s successfully.", db_path)
        return 0
    except OSError as exc:
        logger.error("Failed to write %s: %s", db_path, exc)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Regenerate known_ranges in known_ips.json from official provider feeds."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="Path to known_ips.json (default: project root known_ips.json).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--offline-dir",
        type=Path,
        default=None,
        help="Optional local directory containing goog.json, ip-ranges.json, ips-v4, ips-v6.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and merge feeds without modifying known_ips.json.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = build_parser().parse_args(argv)
    return update_database(
        db_path=args.db,
        timeout=args.timeout,
        offline_dir=args.offline_dir,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
