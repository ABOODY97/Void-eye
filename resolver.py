"""IP-to-service/domain resolver with spoofing defenses, source priority, and timeout rDNS."""

from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
import ipaddress
import json
import logging
from pathlib import Path
import queue
import socket
import threading
import time
from typing import Any, Literal
import unicodedata

from i18n import t

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "known_ips.json"

SourceTag = Literal["known", "sni", "dns", "rdns", "cidr", "special", "raw"]

# Source priority hierarchy: SNI > DNS > rDNS > CIDR (Known exact IP is highest).
SOURCE_PRIORITY: dict[str, int] = {
    "raw": 0,
    "cidr": 10,
    "rdns": 20,
    "dns": 30,
    "sni": 40,
    "known": 50,
    "special": 50,
}

# Names learned passively from network packets or untrusted PTR records.
UNAUTHENTICATED_SOURCES: frozenset[str] = frozenset({"sni", "dns", "rdns"})

CSV_DANGEROUS_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@")

# Common multi-part public suffixes so e.g. sub.bbc.co.uk -> bbc.co.uk
# and portal.haber.com.tr -> haber.com.tr without external HTTP calls.
MULTI_PART_PUBLIC_SUFFIXES: frozenset[str] = frozenset(
    {
        # United Kingdom
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "me.uk",
        "net.uk",
        "plc.uk",
        "ltd.uk",
        # Turkey
        "com.tr",
        "net.tr",
        "org.tr",
        "gov.tr",
        "edu.tr",
        "bel.tr",
        "k12.tr",
        "gen.tr",
        "av.tr",
        "dr.tr",
        "pol.tr",
        "tsk.tr",
        "info.tr",
        "tv.tr",
        "web.tr",
        "name.tr",
        # Middle East & North Africa
        "com.sa",
        "net.sa",
        "org.sa",
        "gov.sa",
        "edu.sa",
        "med.sa",
        "pub.sa",
        "sch.sa",
        "com.eg",
        "net.eg",
        "org.eg",
        "gov.eg",
        "edu.eg",
        "com.ae",
        "net.ae",
        "org.ae",
        "gov.ae",
        "ac.ae",
        "co.ae",
        "com.qa",
        "net.qa",
        "org.qa",
        "gov.qa",
        "edu.qa",
        "com.kw",
        "net.kw",
        "org.kw",
        "gov.kw",
        "edu.kw",
        "com.jo",
        "net.jo",
        "org.jo",
        "gov.jo",
        "edu.jo",
        "com.lb",
        "net.lb",
        "org.lb",
        "gov.lb",
        "edu.lb",
        "co.il",
        "org.il",
        "net.il",
        "ac.il",
        "gov.il",
        # Asia-Pacific
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "asn.au",
        "id.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "ac.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "go.jp",
        "ac.jp",
        "ed.jp",
        "lg.jp",
        "gr.jp",
        "co.kr",
        "ne.kr",
        "or.kr",
        "go.kr",
        "re.kr",
        "pe.kr",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "ac.cn",
        "com.tw",
        "org.tw",
        "gov.tw",
        "edu.tw",
        "net.tw",
        "com.hk",
        "org.hk",
        "edu.hk",
        "gov.hk",
        "net.hk",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "ac.in",
        "res.in",
        "edu.in",
        "com.sg",
        "net.sg",
        "org.sg",
        "gov.sg",
        "edu.sg",
        "com.my",
        "net.my",
        "org.my",
        "gov.my",
        "edu.my",
        "co.id",
        "or.id",
        "go.id",
        "ac.id",
        "web.id",
        "net.id",
        "com.ph",
        "net.ph",
        "org.ph",
        "gov.ph",
        "edu.ph",
        "com.vn",
        "net.vn",
        "org.vn",
        "gov.vn",
        "edu.vn",
        "co.th",
        "in.th",
        "or.th",
        "go.th",
        "ac.th",
        "net.th",
        "com.pk",
        "net.pk",
        "org.pk",
        "gov.pk",
        "edu.pk",
        # Africa
        "co.za",
        "org.za",
        "net.za",
        "gov.za",
        "edu.za",
        "ac.za",
        "com.ng",
        "org.ng",
        "gov.ng",
        "edu.ng",
        "net.ng",
        "co.ke",
        "or.ke",
        "ne.ke",
        "go.ke",
        "ac.ke",
        # Americas & Europe
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "com.ar",
        "net.ar",
        "org.ar",
        "gov.ar",
        "gob.ar",
        "edu.ar",
        "com.mx",
        "net.mx",
        "org.mx",
        "gob.mx",
        "edu.mx",
        "com.co",
        "net.co",
        "org.co",
        "gov.co",
        "edu.co",
        "com.pe",
        "net.pe",
        "org.pe",
        "gob.pe",
        "edu.pe",
        "com.ua",
        "net.ua",
        "org.ua",
        "gov.ua",
        "edu.ua",
        "com.pl",
        "net.pl",
        "org.pl",
        "gov.pl",
        "edu.pl",
        "com.ru",
        "net.ru",
        "org.ru",
        "com.es",
        "nom.es",
        "org.es",
        "gob.es",
        "edu.es",
        "com.pt",
        "org.pt",
        "edu.pt",
        "gov.pt",
        "com.gr",
        "net.gr",
        "org.gr",
        "edu.gr",
        "gov.gr",
    }
)


def sanitize_network_text(
    value: str | bytes | None,
    max_len: int = 253,
) -> str:
    """Neutralize terminal escape/control characters in untrusted packet strings.

    Replaces every non-printable ASCII/Unicode control or format character
    (including ESC \\x1b, BEL, CR/LF, C1 controls, and BiDi overrides) with '?'
    and caps length to *max_len* (RFC 1035 domain limit = 253).
    """
    if value is None or max_len <= 0:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)

    sanitized_chars: list[str] = []
    for ch in text:
        if len(sanitized_chars) >= max_len:
            break
        if not ch.isprintable() or unicodedata.category(ch).startswith("C"):
            sanitized_chars.append("?")
        else:
            sanitized_chars.append(ch)
    return "".join(sanitized_chars)


def sanitize_csv_field(value: Any) -> Any:
    """Prevent spreadsheet formula injection when exporting strings to CSV."""
    if not isinstance(value, str) or not value:
        return value
    if value.startswith(CSV_DANGEROUS_PREFIXES):
        return f"'{value}"
    return value


@dataclass(frozen=True)
class ResolvedHost:
    """Detailed resolution result carrying provenance and shared-IP history."""

    name: str
    source: SourceTag
    recent_names: tuple[str, ...] = ()

    @property
    def is_authenticated(self) -> bool:
        """Return False for names learned passively from network traffic or PTRs."""
        return self.source not in UNAUTHENTICATED_SOURCES

    @property
    def display_name(self) -> str:
        """Return *name* prefixed with '~' when derived from unauthenticated sources."""
        if not self.is_authenticated and self.name:
            return f"~{self.name}"
        return self.name


@dataclass(frozen=True)
class CacheEntry:
    """Single TTL-bounded entry inside the resolver LRU cache."""

    value: str
    source: SourceTag
    expires_at: float
    is_negative: bool = False
    recent_names: tuple[tuple[str, SourceTag], ...] = ()


@dataclass(frozen=True)
class CacheMetrics:
    """Snapshot of resolver cache performance counters."""

    size: int
    max_size: int
    hits: int
    misses: int
    negative_entries: int
    pending_lookups: int


@dataclass
class KnownDatabase:
    """Validated in-memory representation of known_ips.json."""

    known_ips: dict[str, str]
    ipv4_ranges: list[tuple[ipaddress.IPv4Network, str]]
    ipv6_ranges: list[tuple[ipaddress.IPv6Network, str]]
    exact_domains: dict[str, str]
    label_keywords: dict[str, str]


def load_known_database(path: Path | None = None) -> KnownDatabase:
    """Load and validate known_ips.json; degrade gracefully if missing/corrupt."""
    target = path or DEFAULT_DB_PATH
    empty = KnownDatabase(
        known_ips={},
        ipv4_ranges=[],
        ipv6_ranges=[],
        exact_domains={},
        label_keywords={},
    )

    if not target.is_file():
        logger.warning("Known IP database not found at %s; continuing without it.", target)
        return empty

    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to parse known IP database %s: %s", target, exc)
        return empty

    if not isinstance(raw, dict):
        logger.warning("Invalid root type in %s: expected JSON object.", target)
        return empty

    known_ips: dict[str, str] = {}
    raw_ips = raw.get("known_ips", {})
    if isinstance(raw_ips, dict):
        for ip_str, label in raw_ips.items():
            if not isinstance(ip_str, str) or not isinstance(label, str) or not label.strip():
                continue
            try:
                normalized_ip = str(ipaddress.ip_address(ip_str.strip()))
                known_ips[normalized_ip] = label.strip()
            except ValueError:
                logger.warning("Skipping invalid IP in known_ips: %r", ip_str)

    ipv4_ranges: list[tuple[ipaddress.IPv4Network, str]] = []
    ipv6_ranges: list[tuple[ipaddress.IPv6Network, str]] = []
    raw_ranges = raw.get("known_ranges", {})
    if isinstance(raw_ranges, dict):
        for cidr_str, label in raw_ranges.items():
            if not isinstance(cidr_str, str) or not isinstance(label, str) or not label.strip():
                continue
            try:
                net = ipaddress.ip_network(cidr_str.strip(), strict=False)
            except ValueError:
                logger.warning("Skipping invalid CIDR range in known_ranges: %r", cidr_str)
                continue
            if isinstance(net, ipaddress.IPv4Network):
                ipv4_ranges.append((net, label.strip()))
            else:
                ipv6_ranges.append((net, label.strip()))

    # Sort most specific prefixes first (e.g. /24 before /16 before /8).
    ipv4_ranges.sort(key=lambda item: item[0].prefixlen, reverse=True)
    ipv6_ranges.sort(key=lambda item: item[0].prefixlen, reverse=True)

    exact_domains: dict[str, str] = {}
    label_keywords: dict[str, str] = {}
    raw_keywords = raw.get("domain_keywords", {})
    if isinstance(raw_keywords, dict):
        for key, label in raw_keywords.items():
            if not isinstance(key, str) or not isinstance(label, str) or not label.strip():
                continue
            clean_key = key.strip().rstrip(".").lower()
            if not clean_key:
                continue
            if "." in clean_key:
                exact_domains[clean_key] = label.strip()
            else:
                label_keywords[clean_key] = label.strip()

    return KnownDatabase(
        known_ips=known_ips,
        ipv4_ranges=ipv4_ranges,
        ipv6_ranges=ipv6_ranges,
        exact_domains=exact_domains,
        label_keywords=label_keywords,
    )


def extract_registered_domain(hostname: str) -> str:
    """Extract the registrable domain (e.g. 'a.b.bbc.co.uk' -> 'bbc.co.uk')."""
    normalized = sanitize_network_text(hostname).strip().rstrip(".").lower()
    if not normalized:
        return ""

    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass

    labels = [part for part in normalized.split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)

    last_two = f"{labels[-2]}.{labels[-1]}"
    if last_two in MULTI_PART_PUBLIC_SUFFIXES and len(labels) >= 3:
        return f"{labels[-3]}.{last_two}"
    return last_two


def clean_hostname(
    hostname: str,
    exact_domains: dict[str, str] | None = None,
    label_keywords: dict[str, str] | None = None,
) -> str:
    """Map a hostname to a known service name or its clean registered domain."""
    sanitized = sanitize_network_text(hostname)
    normalized = sanitized.strip().rstrip(".").lower()
    if not normalized:
        return sanitized

    reg_domain = extract_registered_domain(normalized)

    if exact_domains:
        if reg_domain in exact_domains:
            return exact_domains[reg_domain]
        for domain_key, service_name in exact_domains.items():
            if normalized == domain_key or normalized.endswith(f".{domain_key}"):
                return service_name

    if label_keywords and reg_domain:
        sld_label = reg_domain.split(".", 1)[0]
        if sld_label in label_keywords:
            return label_keywords[sld_label]

    return reg_domain or normalized


_LAN_IPV4_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_CGNAT_IPV4_NET = ipaddress.IPv4Network("100.64.0.0/10")
_LAN_IPV6_NET = ipaddress.IPv6Network("fc00::/7")


def classify_special_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str | None:
    """Return a translated category label for non-global IPs, or None if global."""
    if addr == ipaddress.IPv4Address("255.255.255.255"):
        return t("ip_broadcast")
    if addr.is_loopback:
        return t("ip_localhost")
    if addr.is_link_local:
        return t("ip_link_local")
    if addr.is_multicast:
        return t("ip_multicast")
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in _CGNAT_IPV4_NET:
            return t("ip_cgnat")
        if any(addr in net for net in _LAN_IPV4_NETS):
            return t("ip_lan")
    elif addr in _LAN_IPV6_NET:
        return t("ip_lan")
    if addr.is_unspecified or addr.is_reserved or not addr.is_global:
        return t("ip_reserved")
    return None


def format_special_ip(ip_text: str, category_label: str) -> str:
    """Format a non-global IP with its translated local category tag."""
    if len(ip_text) > 18:
        return category_label
    return f"{ip_text} ({category_label})"


class _DaemonCallPool:
    """Daemon-thread call executor returning Futures so timed-out rDNS cannot stall workers."""

    def __init__(self, max_workers: int = 8) -> None:
        self._queue: queue.Queue[tuple[Future[str], str] | None] = queue.Queue()
        self._workers: list[threading.Thread] = []
        self._started = False
        self._closed = False
        self._max_workers = max(1, max_workers)
        self._lock = threading.Lock()

    def _ensure_started(self) -> None:
        if self._started or self._closed:
            return
        with self._lock:
            if self._started or self._closed:
                return
            for idx in range(self._max_workers):
                t_worker = threading.Thread(
                    target=self._loop,
                    name=f"void-eye-ptr-{idx}",
                    daemon=True,
                )
                t_worker.start()
                self._workers.append(t_worker)
            self._started = True

    def _loop(self) -> None:
        while not self._closed:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            fut, ip_str = item
            if not fut.set_running_or_notify_cancel():
                self._queue.task_done()
                continue
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
                fut.set_result(hostname)
            except BaseException as exc:
                fut.set_exception(exc)
            finally:
                self._queue.task_done()

    def submit_rdns(self, ip_str: str) -> Future[str]:
        """Submit a blocking gethostbyaddr call and return its Future."""
        self._ensure_started()
        fut: Future[str] = Future()
        if self._closed:
            fut.cancel()
            return fut
        self._queue.put((fut, ip_str))
        return fut

    def shutdown(self) -> None:
        self._closed = True
        if self._started:
            for _ in self._workers:
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    break


DnsQueryKey = tuple[str, str, int, str]  # (client_ip, server_ip, txid, qname)


class Resolver:
    """Thread-safe IP resolver with anti-spoofing, source priority, and bounded rDNS."""

    def __init__(
        self,
        db_path: Path | None = None,
        max_cache_size: int = 2048,
        ttl_seconds: float = 600.0,
        negative_ttl_seconds: float = 120.0,
        rdns_workers: int = 4,
        rdns_timeout: float = 2.0,
        max_pending: int = 256,
        max_recent_names: int = 5,
        dns_query_ttl: float = 10.0,
        max_pending_dns_queries: int = 4096,
        enable_async_rdns: bool = True,
    ) -> None:
        self._db = load_known_database(db_path)
        self._max_cache_size = max(16, max_cache_size)
        self._ttl_seconds = ttl_seconds
        self._negative_ttl_seconds = negative_ttl_seconds
        self._rdns_timeout = max(0.05, rdns_timeout)
        self._max_recent_names = max(1, max_recent_names)
        self._dns_query_ttl = max(0.5, dns_query_ttl)
        self._max_pending_dns_queries = max(32, max_pending_dns_queries)
        self._enable_async_rdns = enable_async_rdns

        self._lock = threading.Lock()
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._pending: dict[str, threading.Event] = {}
        self._pending_dns: OrderedDict[DnsQueryKey, float] = OrderedDict()
        self._hits = 0
        self._misses = 0

        self._rdns_workers = max(1, rdns_workers)
        self._queue: queue.Queue[tuple[str, threading.Event] | None] = queue.Queue(
            maxsize=max(16, max_pending)
        )
        self._ptr_pool = _DaemonCallPool(max_workers=max(4, self._rdns_workers * 2))
        self._workers_started = False
        self._closed = False

    def _ensure_workers(self) -> None:
        """Lazily start daemon coordinator threads on first needed lookup."""
        if self._workers_started or self._closed or not self._enable_async_rdns:
            return
        with self._lock:
            if self._workers_started or self._closed:
                return
            for idx in range(self._rdns_workers):
                worker = threading.Thread(
                    target=self._rdns_worker_loop,
                    name=f"void-eye-rdns-{idx}",
                    daemon=True,
                )
                worker.start()
            self._workers_started = True

    def _rdns_worker_loop(self) -> None:
        """Coordinator worker enforcing Future timeout on each PTR lookup."""
        while not self._closed:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            ip_str, done_event = item
            try:
                self._perform_rdns(ip_str)
            finally:
                with self._lock:
                    self._pending.pop(ip_str, None)
                done_event.set()
                self._queue.task_done()

    def _perform_rdns(self, ip_str: str) -> None:
        """Execute timeout-bounded reverse DNS and record positive or negative cache."""
        fut = self._ptr_pool.submit_rdns(ip_str)
        try:
            raw_host = fut.result(timeout=self._rdns_timeout)
            sanitized = sanitize_network_text(raw_host)
            cleaned = self.clean_domain(sanitized)
            if cleaned:
                self._store_cache(ip_str, cleaned, source="rdns", is_negative=False)
            else:
                self._store_cache(ip_str, ip_str, source="raw", is_negative=True)
        except (
            FutureTimeoutError,
            socket.herror,
            socket.gaierror,
            TimeoutError,
            OSError,
            UnicodeError,
        ):
            fut.cancel()
            self._store_cache(ip_str, ip_str, source="raw", is_negative=True)

    def _get_cached(self, ip_str: str) -> CacheEntry | None:
        """Fetch an unexpired entry from the LRU cache, evicting if expired."""
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(ip_str)
            if entry is None:
                return None
            if now >= entry.expires_at:
                del self._cache[ip_str]
                return None
            self._cache.move_to_end(ip_str)
            self._hits += 1
            return entry

    def _store_cache(
        self,
        ip_str: str,
        value: str,
        *,
        source: SourceTag,
        is_negative: bool,
    ) -> None:
        """Insert or update an entry while enforcing SNI > DNS > rDNS > CIDR priority."""
        now = time.monotonic()
        ttl = self._negative_ttl_seconds if is_negative else self._ttl_seconds
        expires_at = now + ttl

        with self._lock:
            existing = self._cache.get(ip_str)
            if existing is not None and now < existing.expires_at and not existing.is_negative:
                if is_negative:
                    # Never overwrite a valid positive entry with a negative rDNS failure.
                    return

                # Update bounded per-IP history of recent names.
                history = [
                    item
                    for item in existing.recent_names
                    if item != (value, source)
                ]
                history.append((value, source))
                if len(history) > self._max_recent_names:
                    history = history[-self._max_recent_names :]

                new_rank = SOURCE_PRIORITY.get(source, 0)
                cur_rank = SOURCE_PRIORITY.get(existing.source, 0)

                if new_rank >= cur_rank:
                    # Upgrade or refresh with newer equal/higher-priority name (e.g. latest SNI).
                    chosen_val = value
                    chosen_src = source
                else:
                    # Preserve higher-priority source (e.g. never overwrite SNI with DNS/rDNS).
                    chosen_val = existing.value
                    chosen_src = existing.source
                    expires_at = max(existing.expires_at, expires_at)

                self._cache[ip_str] = CacheEntry(
                    value=chosen_val,
                    source=chosen_src,
                    expires_at=expires_at,
                    is_negative=False,
                    recent_names=tuple(history),
                )
            else:
                initial_history: tuple[tuple[str, SourceTag], ...] = (
                    () if is_negative else ((value, source),)
                )
                self._cache[ip_str] = CacheEntry(
                    value=value,
                    source=source,
                    expires_at=expires_at,
                    is_negative=is_negative,
                    recent_names=initial_history,
                )

            self._cache.move_to_end(ip_str)
            while len(self._cache) > self._max_cache_size:
                self._cache.popitem(last=False)

    def clean_domain(self, hostname: str) -> str:
        """Clean *hostname* using this resolver's loaded domain rules."""
        return clean_hostname(
            hostname,
            exact_domains=self._db.exact_domains,
            label_keywords=self._db.label_keywords,
        )

    @staticmethod
    def _normalize_ip_or_empty(ip_str: str) -> str:
        try:
            return str(ipaddress.ip_address(ip_str.strip()))
        except ValueError:
            return ""

    def record_dns_query(
        self,
        client_ip: str,
        server_ip: str,
        txid: int,
        qname: str,
    ) -> None:
        """Record an outbound DNS query so matching responses can be authenticated."""
        c_ip = self._normalize_ip_or_empty(client_ip)
        s_ip = self._normalize_ip_or_empty(server_ip)
        clean_qname = sanitize_network_text(qname).strip().rstrip(".").lower()
        if not c_ip or not s_ip or not clean_qname:
            return

        now = time.monotonic()
        key: DnsQueryKey = (c_ip, s_ip, int(txid) & 0xFFFF, clean_qname)
        with self._lock:
            # Opportunistically prune expired entries from the front of the FIFO.
            while self._pending_dns:
                oldest_key, oldest_exp = next(iter(self._pending_dns.items()))
                if now >= oldest_exp:
                    self._pending_dns.popitem(last=False)
                else:
                    break
            self._pending_dns[key] = now + self._dns_query_ttl
            self._pending_dns.move_to_end(key)
            while len(self._pending_dns) > self._max_pending_dns_queries:
                self._pending_dns.popitem(last=False)

    def learn_dns_response(
        self,
        client_ip: str,
        server_ip: str,
        txid: int,
        qname: str,
        mappings: list[tuple[str, str]],
    ) -> bool:
        """Learn A/AAAA mappings ONLY if matching a recent outbound query."""
        if not mappings:
            return False
        c_ip = self._normalize_ip_or_empty(client_ip)
        s_ip = self._normalize_ip_or_empty(server_ip)
        clean_qname = sanitize_network_text(qname).strip().rstrip(".").lower()
        if not c_ip or not s_ip or not clean_qname:
            return False

        now = time.monotonic()
        key: DnsQueryKey = (c_ip, s_ip, int(txid) & 0xFFFF, clean_qname)
        with self._lock:
            expires_at = self._pending_dns.pop(key, None)
            if expires_at is None or now >= expires_at:
                return False

        learned_any = False
        for mapped_ip, mapped_domain in mappings:
            norm_ip = self._normalize_ip_or_empty(mapped_ip)
            if not norm_ip:
                continue
            addr = ipaddress.ip_address(norm_ip)
            if classify_special_ip(addr) is not None or norm_ip in self._db.known_ips:
                continue
            sanitized_dom = sanitize_network_text(mapped_domain).strip().rstrip(".").lower()
            if not sanitized_dom:
                continue
            display = self.clean_domain(sanitized_dom)
            if display:
                self._store_cache(norm_ip, display, source="dns", is_negative=False)
                learned_any = True
        return learned_any

    def learn_sni(self, ip_str: str, server_name: str) -> None:
        """Record an SNI hostname observed on a TLS/QUIC ClientHello to *ip_str*."""
        norm_ip = self._normalize_ip_or_empty(ip_str)
        if not norm_ip:
            return
        addr = ipaddress.ip_address(norm_ip)
        if classify_special_ip(addr) is not None or norm_ip in self._db.known_ips:
            return
        sanitized = sanitize_network_text(server_name).strip().rstrip(".").lower()
        if not sanitized:
            return
        self._store_cache(norm_ip, sanitized, source="sni", is_negative=False)

    def _match_cidr(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> str | None:
        """Match *addr* against loaded IPv4 or IPv6 CIDR blocks."""
        if isinstance(addr, ipaddress.IPv4Address):
            for net4, label in self._db.ipv4_ranges:
                if addr in net4:
                    return label
        else:
            for net6, label in self._db.ipv6_ranges:
                if addr in net6:
                    return label
        return None

    def resolve_detailed(
        self, ip_str: str, wait_timeout: float = 0.0
    ) -> ResolvedHost:
        """Resolve *ip_str* and return name, provenance source tag, and recent history.

        Priority: Known IP > Special IP > Cache (SNI > DNS > rDNS) > CIDR > Async rDNS.
        """
        raw = sanitize_network_text(ip_str, max_len=64).strip()
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return ResolvedHost(name=raw, source="raw")

        normalized = str(addr)

        # 1. Exact Known IPs
        if normalized in self._db.known_ips:
            with self._lock:
                self._hits += 1
            return ResolvedHost(name=self._db.known_ips[normalized], source="known")

        # 2. Private / CGNAT / Loopback / Link-Local / Multicast / Reserved (never rDNS)
        special_label = classify_special_ip(addr)
        if special_label is not None:
            return ResolvedHost(
                name=format_special_ip(normalized, special_label),
                source="special",
            )

        # 3. Cache (SNI > DNS > rDNS > CIDR & negative cache)
        cached = self._get_cached(normalized)
        if cached is not None:
            recent = tuple(name for name, _ in cached.recent_names)
            src: SourceTag = "raw" if cached.is_negative else cached.source
            return ResolvedHost(name=cached.value, source=src, recent_names=recent)

        with self._lock:
            self._misses += 1

        # 4. Known CIDR Ranges
        cidr_match = self._match_cidr(addr)
        if cidr_match is not None:
            self._store_cache(normalized, cidr_match, source="cidr", is_negative=False)
            return ResolvedHost(
                name=cidr_match,
                source="cidr",
                recent_names=(cidr_match,),
            )

        # 5. Asynchronous Reverse DNS
        if not self._enable_async_rdns or self._closed:
            return ResolvedHost(name=normalized, source="raw")

        self._ensure_workers()
        done_event: threading.Event | None = None
        enqueue_needed = False

        with self._lock:
            existing_event = self._pending.get(normalized)
            if existing_event is not None:
                done_event = existing_event
            elif not self._queue.full():
                done_event = threading.Event()
                self._pending[normalized] = done_event
                enqueue_needed = True

        if enqueue_needed and done_event is not None:
            try:
                self._queue.put_nowait((normalized, done_event))
            except queue.Full:
                with self._lock:
                    self._pending.pop(normalized, None)
                done_event = None

        if wait_timeout > 0.0 and done_event is not None:
            if done_event.wait(timeout=wait_timeout):
                ready = self._get_cached(normalized)
                if ready is not None:
                    recent = tuple(name for name, _ in ready.recent_names)
                    src = "raw" if ready.is_negative else ready.source
                    return ResolvedHost(name=ready.value, source=src, recent_names=recent)

        return ResolvedHost(name=normalized, source="raw")

    def resolve(self, ip_str: str, wait_timeout: float = 0.0) -> str:
        """Resolve *ip_str* to a clean host/label string without blocking capture."""
        return self.resolve_detailed(ip_str, wait_timeout=wait_timeout).name

    def metrics(self) -> CacheMetrics:
        """Return a thread-safe snapshot of cache metrics."""
        now = time.monotonic()
        with self._lock:
            expired = [k for k, v in self._cache.items() if now >= v.expires_at]
            for k in expired:
                del self._cache[k]
            neg_count = sum(1 for v in self._cache.values() if v.is_negative)
            return CacheMetrics(
                size=len(self._cache),
                max_size=self._max_cache_size,
                hits=self._hits,
                misses=self._misses,
                negative_entries=neg_count,
                pending_lookups=len(self._pending),
            )

    def stats_string(self) -> str:
        """Return a translated human-readable summary of cache metrics."""
        m = self.metrics()
        return t(
            "cache_stats_fmt",
            size=m.size,
            max_size=m.max_size,
            hits=m.hits,
            misses=m.misses,
            neg=m.negative_entries,
            pending=m.pending_lookups,
        )

    def shutdown(self) -> None:
        """Signal background rDNS threads to stop without blocking exit."""
        self._closed = True
        self._ptr_pool.shutdown()
        if self._workers_started:
            for _ in range(self._rdns_workers):
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    break


_default_resolver: Resolver | None = None
_default_lock = threading.Lock()


def get_resolver() -> Resolver:
    """Return the lazily initialized default Resolver instance."""
    global _default_resolver
    if _default_resolver is None:
        with _default_lock:
            if _default_resolver is None:
                _default_resolver = Resolver()
    return _default_resolver


def resolve(ip_str: str, wait_timeout: float = 0.0) -> str:
    """Resolve *ip_str* using the default Resolver instance."""
    return get_resolver().resolve(ip_str, wait_timeout=wait_timeout)


def cache_stats() -> str:
    """Return formatted cache statistics for the default Resolver."""
    return get_resolver().stats_string()
