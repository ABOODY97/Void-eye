"""Non-blocking packet capture, TLS/QUIC SNI dissection, DNS validation, and export."""

from __future__ import annotations

from collections import Counter, OrderedDict
import csv
import ctypes
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import queue
import socket
import struct
import threading
import time
from typing import TYPE_CHECKING, Any, TextIO

from i18n import t
from resolver import (
    Resolver,
    SourceTag,
    get_resolver,
    sanitize_csv_field,
    sanitize_network_text,
)
import ui

if TYPE_CHECKING:
    from scapy.all import Packet, PcapWriter  # type: ignore[import-untyped]


@lru_cache(maxsize=1)
def _scapy() -> Any:
    """Lazily import Scapy symbols on first packet/interface operation (zero import-time I/O)."""
    import scapy.all as scapy_all  # type: ignore[import-untyped]

    return scapy_all

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - optional runtime fallback
    HAS_CRYPTOGRAPHY = False

WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Srv",
    68: "DHCP-Cli",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Sub",
    636: "LDAPS",
    853: "DoT",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle",
    1883: "MQTT",
    1900: "SSDP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    3478: "STUN",
    5353: "mDNS",
    5355: "LLMNR",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    6443: "K8s-API",
    8000: "HTTP-Dev",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTTS",
    9200: "Elastic",
    11211: "Memcached",
    27017: "MongoDB",
    51820: "WireGuard",
}

ICMPV4_TYPES: dict[int, str] = {
    0: "Echo Reply",
    3: "Dest Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}

ICMPV6_TYPES: dict[int, str] = {
    1: "Dest Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
}

PROTOCOL_BPF_MAP: dict[str, str] = {
    "all": "",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp or icmp6",
    "dns": "port 53",
    "arp": "arp",
    "ipv6": "ip6",
}

# RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2) Initial packet constants
_QUIC_V1 = 0x00000001
_QUIC_V2 = 0x6B3343CF
_QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
_QUIC_V2_SALT = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")


@dataclass(frozen=True)
class InterfaceInfo:
    """Friendly cross-platform representation of a capture interface."""

    scapy_iface: str
    name: str
    description: str
    ipv4: str | None
    ipv6: str | None

    @property
    def display_name(self) -> str:
        """Human-friendly adapter label combining short name and description."""
        if self.description and self.description.lower() != self.name.lower():
            return f"{self.name} ({self.description})"
        return self.name


@dataclass
class CaptureSettings:
    """Mutable capture filter, limit, and export configuration."""

    bpf_filter: str = ""
    protocol_filter: str = "all"
    pcap_path: Path | None = None
    log_path: Path | None = None
    max_packets: int = 0
    duration_limit: float = 0.0

    def reset(self) -> None:
        """Restore default capture settings."""
        self.bpf_filter = ""
        self.protocol_filter = "all"
        self.pcap_path = None
        self.log_path = None
        self.max_packets = 0
        self.duration_limit = 0.0

    def effective_bpf(self) -> str:
        """Combine user BPF expression with the selected protocol filter."""
        proto_expr = PROTOCOL_BPF_MAP.get(self.protocol_filter.lower(), "")
        custom = self.bpf_filter.strip()
        if custom and proto_expr:
            return f"({custom}) and ({proto_expr})"
        return custom or proto_expr


@dataclass(frozen=True)
class DnsPacketInfo:
    """Sanitized DNS header and answer data extracted from a packet."""

    txid: int
    is_response: bool
    qname: str | None
    answers: list[tuple[str, str]]


@dataclass(frozen=True)
class PacketRecord:
    """Normalized dissected packet information for display and export."""

    timestamp_iso: str
    timestamp_short: str
    protocol: str
    network_layer: str
    src_ip: str
    src_display: str
    src_source: SourceTag
    sport: int | None
    dst_ip: str
    dst_display: str
    dst_host: str
    dst_source: SourceTag
    dport: int | None
    length: int
    info: str


@dataclass
class CaptureStats:
    """Aggregated traffic metrics collected during a capture session."""

    total_packets: int = 0
    dropped_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    protocol_counts: Counter[str] = field(default_factory=Counter)
    destination_packets: Counter[str] = field(default_factory=Counter)
    destination_bytes: Counter[str] = field(default_factory=Counter)
    saved_files: list[Path] = field(default_factory=list)


def has_capture_privileges() -> bool:
    """Return True if running as root (POSIX) or Administrator (Windows)."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return True


@lru_cache(maxsize=1024)
def get_service_name(port: int, proto: str = "tcp") -> str:
    """Map a TCP/UDP port number to a service name with OS service-db fallback."""
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]
    if port >= 49152 or port <= 0:
        return str(port)
    try:
        return socket.getservbyport(port, proto.lower()).upper()
    except OSError:
        return str(port)


def _is_valid_ip(ip_text: str | None) -> bool:
    """Return True if *ip_text* is a valid non-unspecified IPv4/IPv6 address."""
    if not ip_text:
        return False
    cleaned = ip_text.split("%", 1)[0].strip()
    if not cleaned or cleaned == "0.0.0.0" or cleaned == "::":
        return False
    try:
        addr = ipaddress.ip_address(cleaned)
        return not addr.is_unspecified
    except ValueError:
        return False


def list_interfaces() -> list[InterfaceInfo]:
    """Enumerate interfaces via scapy.conf.ifaces, skipping adapters without valid IPs."""
    results: list[InterfaceInfo] = []
    try:
        sc = _scapy()
        iface_values = list(sc.conf.ifaces.values())
    except Exception:
        return results

    for iface in iface_values:
        name = sanitize_network_text(getattr(iface, "name", ""), max_len=120).strip()
        description = sanitize_network_text(
            getattr(iface, "description", ""), max_len=160
        ).strip()
        scapy_id = str(getattr(iface, "network_name", "") or name).strip()
        if not scapy_id:
            continue

        raw_ip = str(getattr(iface, "ip", "") or "").strip()
        ips_map = getattr(iface, "ips", {}) or {}

        ipv4: str | None = raw_ip if _is_valid_ip(raw_ip) else None
        if ipv4 is None and isinstance(ips_map, dict):
            for candidate in ips_map.get(4, []):
                if _is_valid_ip(str(candidate)):
                    ipv4 = str(candidate)
                    break

        ipv6: str | None = None
        if isinstance(ips_map, dict):
            for candidate in ips_map.get(6, []):
                cand_str = str(candidate).split("%", 1)[0]
                if _is_valid_ip(cand_str):
                    ipv6 = cand_str
                    try:
                        if ipaddress.ip_address(cand_str).is_global:
                            break
                    except ValueError:
                        pass

        if ipv4 is None and ipv6 is None:
            continue

        friendly_name = name or description or scapy_id
        results.append(
            InterfaceInfo(
                scapy_iface=scapy_id,
                name=friendly_name,
                description=description,
                ipv4=ipv4,
                ipv6=ipv6,
            )
        )

    results.sort(key=lambda item: (item.ipv4 is None, item.display_name.lower()))
    return results


def find_interface(
    query: str, interfaces: list[InterfaceInfo] | None = None
) -> InterfaceInfo | None:
    """Resolve a CLI --iface argument by index, friendly name, GUID, or IP."""
    available = interfaces if interfaces is not None else list_interfaces()
    needle = query.strip()
    if not needle:
        return None

    if needle.isdigit():
        idx = int(needle) - 1
        if 0 <= idx < len(available):
            return available[idx]

    lowered = needle.lower()
    for iface in available:
        candidates = (
            iface.name.lower(),
            iface.description.lower(),
            iface.display_name.lower(),
            iface.scapy_iface.lower(),
            (iface.ipv4 or "").lower(),
            (iface.ipv6 or "").lower(),
        )
        if lowered in candidates:
            return iface

    for iface in available:
        if lowered in iface.display_name.lower() or lowered in iface.scapy_iface.lower():
            return iface
    return None


def _inspect_tls_client_hello(
    payload: bytes, max_record_bytes: int = 16389
) -> tuple[str | None, int | None]:
    """Inspect a raw TLS Handshake buffer for SNI.

    Returns ``(sni, needed_total_bytes)``:
    - ``(sni, None)`` when SNI is extracted.
    - ``(None, needed_bytes)`` when *payload* is a valid partial ClientHello
      truncated mid-record across TCP segments.
    - ``(None, None)`` when *payload* is not a ClientHello or lacks SNI.
    """
    data_len = len(payload)
    if data_len == 0 or payload[0] != 0x16:
        return None, None
    if data_len >= 2 and payload[1] != 0x03:
        return None, None
    if data_len < 5:
        return None, 5

    record_len = struct.unpack("!H", payload[3:5])[0]
    if record_len == 0 or 5 + record_len > max_record_bytes:
        return None, None
    expected_total = 5 + record_len

    if data_len < 6:
        return None, expected_total
    if payload[5] != 0x01:  # HandshakeType ClientHello
        return None, None
    if data_len < 9:
        return None, expected_total

    handshake_len = int.from_bytes(payload[6:9], "big")
    end_hs = min(expected_total, 9 + handshake_len)
    avail = min(data_len, end_hs)
    incomplete = data_len < end_hs

    # Skip client_version (2B) + random (32B)
    pos = 9 + 2 + 32
    if pos + 1 > avail:
        return (None, end_hs) if incomplete else (None, None)

    session_id_len = payload[pos]
    pos += 1 + session_id_len
    if pos + 2 > avail:
        return (None, end_hs) if incomplete else (None, None)

    cipher_suites_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2 + cipher_suites_len
    if pos + 1 > avail:
        return (None, end_hs) if incomplete else (None, None)

    comp_methods_len = payload[pos]
    pos += 1 + comp_methods_len
    if pos + 2 > avail:
        return (None, end_hs) if incomplete else (None, None)

    extensions_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2
    end_ext = min(end_hs, pos + extensions_len)
    avail_ext = min(avail, end_ext)

    while pos + 4 <= avail_ext:
        ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
        pos += 4
        if pos + ext_len > avail_ext:
            return (None, end_hs) if incomplete else (None, None)

        if ext_type == 0x0000 and ext_len >= 5:  # server_name
            list_len = struct.unpack("!H", payload[pos : pos + 2])[0]
            sni_pos = pos + 2
            sni_end = min(pos + ext_len, sni_pos + list_len)
            while sni_pos + 3 <= sni_end:
                name_type = payload[sni_pos]
                name_len = struct.unpack("!H", payload[sni_pos + 1 : sni_pos + 3])[0]
                sni_pos += 3
                if sni_pos + name_len > sni_end:
                    return None, None
                if name_type == 0x00 and name_len > 0:
                    raw_host = payload[sni_pos : sni_pos + name_len]
                    sanitized = (
                        sanitize_network_text(raw_host).strip().rstrip(".").lower()
                    )
                    if sanitized and "." in sanitized and "?" not in sanitized:
                        return sanitized, None
                    return None, None
                sni_pos += name_len
            return None, None

        pos += ext_len

    if incomplete and pos < end_ext:
        return None, end_hs
    return None, None


def extract_tls_sni(payload: bytes) -> str | None:
    """Extract and sanitize SNI from a single-buffer TLS ClientHello payload."""
    sni, _ = _inspect_tls_client_hello(payload)
    return sni


FlowKey = tuple[str, int, str, int]


@dataclass
class _TcpFlowBuffer:
    """Bounded per-flow state reassembling a multi-segment TLS ClientHello."""

    base_seq: int
    expected_len: int
    created_at: float
    segments: dict[int, bytes] = field(default_factory=dict)
    buffered_bytes: int = 0

    def assemble_contiguous(self) -> bytes:
        """Assemble contiguous bytes starting from *base_seq*."""
        out = bytearray()
        cursor = self.base_seq
        for seg_seq in sorted(self.segments.keys()):
            seg_data = self.segments[seg_seq]
            # Compute 32-bit unsigned modular offset relative to base_seq
            rel = (seg_seq - self.base_seq) & 0xFFFFFFFF
            if rel > 65536:
                continue
            seg_start = self.base_seq + rel
            if seg_start > cursor:
                break
            overlap = cursor - seg_start
            if overlap < len(seg_data):
                chunk = seg_data[overlap:]
                out.extend(chunk)
                cursor += len(chunk)
        return bytes(out)


class TlsStreamReassembler:
    """Bounded TCP segment reassembler for multi-segment TLS ClientHello records."""

    def __init__(
        self,
        max_flows: int = 512,
        max_buffer_bytes: int = 16389,
        max_segments_per_flow: int = 12,
        ttl_seconds: float = 10.0,
    ) -> None:
        self._max_flows = max(16, max_flows)
        self._max_buffer_bytes = max(1024, max_buffer_bytes)
        self._max_segments = max(2, max_segments_per_flow)
        self._ttl_seconds = max(1.0, ttl_seconds)
        self._flows: OrderedDict[FlowKey, _TcpFlowBuffer] = OrderedDict()

    def _prune_expired(self, now: float) -> None:
        while self._flows:
            _, oldest = next(iter(self._flows.items()))
            if now - oldest.created_at >= self._ttl_seconds:
                self._flows.popitem(last=False)
            else:
                break

    def feed(
        self,
        flow: FlowKey,
        seq: int,
        payload: bytes,
        *,
        tcp_flags: int = 0,
        timestamp: float | None = None,
    ) -> str | None:
        """Feed a TCP segment and return sanitized SNI once reassembled."""
        now = timestamp if timestamp is not None else time.monotonic()
        self._prune_expired(now)

        # Tear down state on FIN (0x01) or RST (0x04) if no payload
        if (tcp_flags & 0x05) and not payload:
            self._flows.pop(flow, None)
            return None

        if not payload:
            return None

        existing = self._flows.get(flow)
        if existing is None:
            sni, needed = _inspect_tls_client_hello(payload, self._max_buffer_bytes)
            if sni is not None:
                return sni
            if needed is None or len(payload) >= self._max_buffer_bytes:
                return None

            buf = _TcpFlowBuffer(
                base_seq=seq & 0xFFFFFFFF,
                expected_len=min(needed, self._max_buffer_bytes),
                created_at=now,
                segments={seq & 0xFFFFFFFF: payload},
                buffered_bytes=len(payload),
            )
            self._flows[flow] = buf
            while len(self._flows) > self._max_flows:
                self._flows.popitem(last=False)
            return None

        # Existing partial ClientHello flow
        norm_seq = seq & 0xFFFFFFFF
        if norm_seq not in existing.segments:
            if (
                len(existing.segments) >= self._max_segments
                or existing.buffered_bytes + len(payload) > self._max_buffer_bytes * 2
            ):
                self._flows.pop(flow, None)
                return None
            existing.segments[norm_seq] = payload
            existing.buffered_bytes += len(payload)
        elif len(payload) > len(existing.segments[norm_seq]):
            existing.buffered_bytes += len(payload) - len(existing.segments[norm_seq])
            existing.segments[norm_seq] = payload

        self._flows.move_to_end(flow)
        assembled = existing.assemble_contiguous()
        sni, needed = _inspect_tls_client_hello(assembled, self._max_buffer_bytes)
        if sni is not None:
            self._flows.pop(flow, None)
            return sni

        if needed is None or len(assembled) >= existing.expected_len or (tcp_flags & 0x05):
            self._flows.pop(flow, None)
        return None


def _read_quic_varint(buf: bytes, pos: int) -> tuple[int, int] | None:
    """Decode an RFC 9000 Section 16 variable-length integer at *pos*."""
    if pos >= len(buf):
        return None
    prefix = buf[pos] >> 6
    length = 1 << prefix
    if pos + length > len(buf):
        return None
    val = buf[pos] & 0x3F
    for idx in range(1, length):
        val = (val << 8) | buf[pos + idx]
    return val, pos + length


def _hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract using SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, full_label: bytes, out_len: int) -> bytes:
    """RFC 8446 Section 7.1 HKDF-Expand-Label with empty context."""
    hkdf_label = struct.pack("!HB", out_len, len(full_label)) + full_label + b"\x00"
    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < out_len:
        prev = hmac.new(
            secret, prev + hkdf_label + bytes([counter]), hashlib.sha256
        ).digest()
        out.extend(prev)
        counter += 1
    return bytes(out[:out_len])


def is_likely_quic_packet(payload: bytes) -> bool:
    """Heuristic check for a QUIC Long Header packet on UDP 443."""
    if len(payload) < 32:
        return False
    first = payload[0]
    if (first & 0xC0) != 0xC0:
        return False
    version = struct.unpack("!I", payload[1:5])[0]
    return version in {_QUIC_V1, _QUIC_V2} or (version & 0xFF000000) == 0xFF000000


def extract_quic_sni(payload: bytes) -> str | None:
    """Decrypt a QUIC v1/v2 Initial packet (RFC 9001) and extract TLS 1.3 SNI.

    Falls back cleanly to None when *cryptography* is unavailable or when the
    datagram is not an Initial ClientHello packet.
    """
    if not HAS_CRYPTOGRAPHY or len(payload) < 64:
        return None

    first = payload[0]
    # Long Header (0x80) + Fixed Bit (0x40)
    if (first & 0xC0) != 0xC0:
        return None

    version = struct.unpack("!I", payload[1:5])[0]
    pkt_type = (first & 0x30) >> 4

    if version == _QUIC_V1 and pkt_type == 0x00:
        salt = _QUIC_V1_SALT
        lbl_key = b"tls13 quic key"
        lbl_iv = b"tls13 quic iv"
        lbl_hp = b"tls13 quic hp"
    elif version == _QUIC_V2 and pkt_type == 0x01:
        salt = _QUIC_V2_SALT
        lbl_key = b"tls13 quicv2 key"
        lbl_iv = b"tls13 quicv2 iv"
        lbl_hp = b"tls13 quicv2 hp"
    else:
        return None

    pos = 5
    dcid_len = payload[pos]
    pos += 1
    if dcid_len > 20 or pos + dcid_len + 1 > len(payload):
        return None
    dcid = payload[pos : pos + dcid_len]
    pos += dcid_len

    scid_len = payload[pos]
    pos += 1
    if scid_len > 20 or pos + scid_len > len(payload):
        return None
    pos += scid_len

    tok_res = _read_quic_varint(payload, pos)
    if tok_res is None:
        return None
    token_len, pos = tok_res
    pos += token_len

    len_res = _read_quic_varint(payload, pos)
    if len_res is None:
        return None
    rem_len, pn_offset = len_res

    if rem_len < 20 or pn_offset + rem_len > len(payload) or pn_offset + 20 > len(payload):
        return None

    initial_secret = _hkdf_extract_sha256(salt, dcid)
    client_secret = _hkdf_expand_label(initial_secret, b"tls13 client in", 32)
    key = _hkdf_expand_label(client_secret, lbl_key, 16)
    iv = _hkdf_expand_label(client_secret, lbl_iv, 12)
    hp_key = _hkdf_expand_label(client_secret, lbl_hp, 16)

    sample = payload[pn_offset + 4 : pn_offset + 20]
    hp_cipher = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = hp_cipher.update(sample) + hp_cipher.finalize()

    unmasked_first = first ^ (mask[0] & 0x0F)
    pn_len = (unmasked_first & 0x03) + 1
    if rem_len < pn_len + 16:
        return None

    buf = bytearray(payload[: pn_offset + rem_len])
    buf[0] = unmasked_first
    pn_val = 0
    for idx in range(pn_len):
        buf[pn_offset + idx] ^= mask[1 + idx]
        pn_val = (pn_val << 8) | buf[pn_offset + idx]

    aad = bytes(buf[: pn_offset + pn_len])
    ciphertext = bytes(buf[pn_offset + pn_len : pn_offset + rem_len])
    nonce = (int.from_bytes(iv, "big") ^ pn_val).to_bytes(12, "big")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError):
        return None

    crypto_segments: dict[int, bytes] = {}
    fpos = 0
    while fpos < len(plaintext):
        ft_res = _read_quic_varint(plaintext, fpos)
        if ft_res is None:
            break
        ftype, fpos = ft_res
        if ftype in {0x00, 0x01}:  # PADDING / PING
            continue
        if ftype == 0x06:  # CRYPTO frame
            off_res = _read_quic_varint(plaintext, fpos)
            if off_res is None:
                break
            c_offset, fpos = off_res
            clen_res = _read_quic_varint(plaintext, fpos)
            if clen_res is None:
                break
            c_len, fpos = clen_res
            if fpos + c_len > len(plaintext):
                break
            crypto_segments[c_offset] = plaintext[fpos : fpos + c_len]
            fpos += c_len
        else:
            break

    if 0 not in crypto_segments:
        return None

    hs_bytes = bytearray()
    cursor = 0
    for seg_off in sorted(crypto_segments.keys()):
        if seg_off > cursor:
            break
        seg = crypto_segments[seg_off]
        overlap = cursor - seg_off
        if overlap < len(seg):
            hs_bytes.extend(seg[overlap:])
            cursor = seg_off + len(seg)

    if len(hs_bytes) < 4 or hs_bytes[0] != 0x01 or len(hs_bytes) > 16384:
        return None

    # Wrap raw TLS Handshake message in a synthetic TLS record header for parser reuse
    synthetic_record = b"\x16\x03\x03" + struct.pack("!H", len(hs_bytes)) + bytes(hs_bytes)
    return extract_tls_sni(synthetic_record)


def _decode_dns_name(raw_name: Any) -> str:
    """Decode and sanitize a Scapy DNS domain field into a safe hostname."""
    return sanitize_network_text(raw_name).strip().rstrip(".").lower()


def extract_dns_info(packet: Packet) -> DnsPacketInfo | None:
    """Extract sanitized (txid, is_response, qname, answers) from a DNS packet."""
    sc = _scapy()
    if not packet.haslayer(sc.DNS):
        return None

    dns_layer = packet[sc.DNS]
    txid = int(getattr(dns_layer, "id", 0)) & 0xFFFF
    is_response = bool(getattr(dns_layer, "qr", 0))
    qname: str | None = None

    if packet.haslayer(sc.DNSQR):
        candidate = _decode_dns_name(getattr(packet[sc.DNSQR], "qname", b""))
        if candidate:
            qname = candidate

    mappings: list[tuple[str, str]] = []
    raw_an = getattr(dns_layer, "an", None)
    if is_response and raw_an:
        answers: list[Any] = []
        if isinstance(raw_an, list):
            answers.extend(raw_an)
        else:
            cur = raw_an
            while isinstance(cur, sc.DNSRR):
                answers.append(cur)
                cur = cur.payload if isinstance(cur.payload, sc.DNSRR) else None

        cname_map: dict[str, str] = {}
        ip_records: list[tuple[str, str]] = []

        for answer in answers:
            if not isinstance(answer, sc.DNSRR):
                continue
            rrname = _decode_dns_name(getattr(answer, "rrname", b""))
            rtype = getattr(answer, "type", 0)
            rdata = getattr(answer, "rdata", None)
            if rtype == 5 and rdata:  # CNAME
                target = _decode_dns_name(rdata)
                if rrname and target:
                    cname_map[target] = rrname
            elif rtype in {1, 28} and rdata:  # A or AAAA
                ip_str = _decode_dns_name(rdata)
                if ip_str:
                    ip_records.append((ip_str, rrname))

        for ip_str, owner in ip_records:
            domain = qname or cname_map.get(owner, owner)
            if domain:
                mappings.append((ip_str, domain))

    return DnsPacketInfo(
        txid=txid,
        is_response=is_response,
        qname=qname,
        answers=mappings,
    )


def dissect_packet(
    packet: Packet,
    resolver: Resolver,
    tls_reassembler: TlsStreamReassembler | None = None,
) -> PacketRecord | None:
    """Dissect IPv4, IPv6, or ARP packet using packet.time and sanitized fields."""
    sc = _scapy()
    raw_time = getattr(packet, "time", None)
    pkt_epoch = float(raw_time) if raw_time is not None else time.time()
    pkt_dt = datetime.fromtimestamp(pkt_epoch)
    ts_iso = pkt_dt.isoformat(timespec="milliseconds")
    ts_short = pkt_dt.strftime("%H:%M:%S")
    pkt_len = len(packet)

    # 1. ARP packets
    if packet.haslayer(sc.ARP):
        arp = packet[sc.ARP]
        src_ip = sanitize_network_text(getattr(arp, "psrc", ""), max_len=64).strip()
        dst_ip = sanitize_network_text(getattr(arp, "pdst", ""), max_len=64).strip()
        hwsrc = sanitize_network_text(getattr(arp, "hwsrc", ""), max_len=32).strip()
        hwdst = sanitize_network_text(getattr(arp, "hwdst", ""), max_len=32).strip()

        src_res = resolver.resolve_detailed(src_ip) if src_ip else None
        dst_res = resolver.resolve_detailed(dst_ip) if dst_ip else None
        src_disp = src_res.display_name if src_res else hwsrc
        dst_disp = dst_res.display_name if dst_res else hwdst

        op = int(getattr(arp, "op", 0))
        if op == 1:
            info = f"Who has {dst_ip}? Tell {src_ip}"
        elif op == 2:
            info = f"{src_ip} is at {hwsrc}"
        else:
            info = f"ARP op={op}"

        return PacketRecord(
            timestamp_iso=ts_iso,
            timestamp_short=ts_short,
            protocol="ARP",
            network_layer="ARP",
            src_ip=src_ip,
            src_display=src_disp,
            src_source=src_res.source if src_res else "raw",
            sport=None,
            dst_ip=dst_ip,
            dst_display=dst_disp,
            dst_host=dst_disp,
            dst_source=dst_res.source if dst_res else "raw",
            dport=None,
            length=pkt_len,
            info=info,
        )

    # 2. IPv4 / IPv6 packets
    if packet.haslayer(sc.IP):
        net_layer = "IPv4"
        src_ip = sanitize_network_text(packet[sc.IP].src, max_len=64).strip()
        dst_ip = sanitize_network_text(packet[sc.IP].dst, max_len=64).strip()
        ip_proto = int(getattr(packet[sc.IP], "proto", 0))
    elif packet.haslayer(sc.IPv6):
        net_layer = "IPv6"
        src_ip = sanitize_network_text(packet[sc.IPv6].src, max_len=64).strip()
        dst_ip = sanitize_network_text(packet[sc.IPv6].dst, max_len=64).strip()
        ip_proto = int(getattr(packet[sc.IPv6], "nh", 0))
    else:
        return None

    # Validate DNS queries/responses BEFORE resolving endpoints
    dns_info = extract_dns_info(packet)
    if dns_info is not None and dns_info.qname:
        if not dns_info.is_response:
            resolver.record_dns_query(src_ip, dst_ip, dns_info.txid, dns_info.qname)
        elif dns_info.answers:
            resolver.learn_dns_response(
                client_ip=dst_ip,
                server_ip=src_ip,
                txid=dns_info.txid,
                qname=dns_info.qname,
                mappings=dns_info.answers,
            )

    src_res = resolver.resolve_detailed(src_ip)
    dst_res = resolver.resolve_detailed(dst_ip)
    src_disp = src_res.display_name
    dst_disp = dst_res.display_name
    dst_host = dst_res.display_name
    src_source: SourceTag = src_res.source
    dst_source: SourceTag = dst_res.source

    protocol = net_layer
    sport: int | None = None
    dport: int | None = None
    info = ""

    if packet.haslayer(sc.TCP):
        tcp = packet[sc.TCP]
        sport = int(tcp.sport)
        dport = int(tcp.dport)
        s_srv = get_service_name(sport, "tcp")
        d_srv = get_service_name(dport, "tcp")
        protocol = "TCP"
        info = f"{s_srv} -> {d_srv}"

        raw_payload = bytes(tcp.payload)
        sni: str | None = None
        if tls_reassembler is not None:
            flow: FlowKey = (src_ip, sport, dst_ip, dport)
            sni = tls_reassembler.feed(
                flow,
                int(getattr(tcp, "seq", 0)),
                raw_payload,
                tcp_flags=int(getattr(tcp, "flags", 0)),
                timestamp=pkt_epoch,
            )
        elif raw_payload:
            sni = extract_tls_sni(raw_payload)

        if sni:
            protocol = "TLS"
            resolver.learn_sni(dst_ip, sni)
            dst_disp = f"~{sni}"
            dst_host = dst_disp
            dst_source = "sni"
            info = f"{s_srv} -> {d_srv} [SNI: {sni}]"
        elif dns_info is not None and dns_info.qname:
            protocol = "DNS"
            tag = "Ans" if dns_info.is_response else "Q"
            info = f"{s_srv} -> {d_srv} [{tag}: {dns_info.qname}]"

    elif packet.haslayer(sc.UDP):
        udp = packet[sc.UDP]
        sport = int(udp.sport)
        dport = int(udp.dport)
        s_srv = get_service_name(sport, "udp")
        d_srv = get_service_name(dport, "udp")
        protocol = "UDP"
        info = f"{s_srv} -> {d_srv}"

        raw_udp = bytes(udp.payload)
        if dns_info is not None and dns_info.qname:
            # Keep DNS server visible in src/dst columns and show qname in info!
            protocol = "DNS"
            tag = "Ans" if dns_info.is_response else "Q"
            info = f"{s_srv} -> {d_srv} [{tag}: {dns_info.qname}]"
        elif raw_udp and (dport == 443 or sport == 443):
            quic_sni = extract_quic_sni(raw_udp)
            if quic_sni:
                protocol = "QUIC"
                resolver.learn_sni(dst_ip, quic_sni)
                dst_disp = f"~{quic_sni}"
                dst_host = dst_disp
                dst_source = "sni"
                info = f"{s_srv} -> {d_srv} [QUIC SNI: {quic_sni}]"
            elif is_likely_quic_packet(raw_udp):
                protocol = "QUIC"
                info = f"{s_srv} -> QUIC"

    elif packet.haslayer(sc.ICMP):
        icmp_type = int(getattr(packet[sc.ICMP], "type", -1))
        icmp_code = int(getattr(packet[sc.ICMP], "code", 0))
        type_desc = ICMPV4_TYPES.get(icmp_type, f"Type {icmp_type}")
        protocol = "ICMP"
        info = f"{type_desc} (code={icmp_code})"

    elif ip_proto == 58:  # ICMPv6
        protocol = "ICMPv6"
        icmp6_layer = packet[sc.IPv6].payload
        icmp6_type = int(getattr(icmp6_layer, "type", -1))
        type_desc = ICMPV6_TYPES.get(icmp6_type, f"Type {icmp6_type}")
        info = type_desc

    return PacketRecord(
        timestamp_iso=ts_iso,
        timestamp_short=ts_short,
        protocol=protocol,
        network_layer=net_layer,
        src_ip=src_ip,
        src_display=src_disp,
        src_source=src_source,
        sport=sport,
        dst_ip=dst_ip,
        dst_display=dst_disp,
        dst_host=dst_host,
        dst_source=dst_source,
        dport=dport,
        length=pkt_len,
        info=info,
    )


class PacketRecorder:
    """Buffered context manager writing packets to .pcap (periodic flush) and .csv/.jsonl."""

    FLUSH_PACKET_INTERVAL = 64
    FLUSH_TIME_INTERVAL = 1.0

    def __init__(self, pcap_path: Path | None, log_path: Path | None) -> None:
        self._pcap_path = pcap_path
        self._log_path = log_path
        self._pcap_writer: PcapWriter | None = None
        self._log_fp: TextIO | None = None
        self._csv_writer: Any = None
        self._is_jsonl = False
        self._since_flush = 0
        self._last_flush = time.monotonic()
        self.active_files: list[Path] = []

    def __enter__(self) -> PacketRecorder:
        if self._pcap_path is not None:
            sc = _scapy()
            try:
                self._pcap_path.parent.mkdir(parents=True, exist_ok=True)
                self._pcap_writer = sc.PcapWriter(
                    str(self._pcap_path), append=False, sync=False
                )
                self.active_files.append(self._pcap_path)
            except (OSError, sc.Scapy_Exception) as exc:
                print(
                    f"{ui.RED}"
                    f"{t('file_open_error', path=self._pcap_path, error=exc)}"
                    f"{ui.RESET}"
                )
                self._pcap_writer = None

        if self._log_path is not None:
            try:
                self._log_path.parent.mkdir(parents=True, exist_ok=True)
                self._is_jsonl = self._log_path.suffix.lower() in {".jsonl", ".json"}
                self._log_fp = self._log_path.open("w", encoding="utf-8", newline="")
                if not self._is_jsonl:
                    self._csv_writer = csv.writer(self._log_fp)
                    self._csv_writer.writerow(
                        [
                            "timestamp",
                            "protocol",
                            "network_layer",
                            "src_ip",
                            "src_name",
                            "src_source",
                            "src_port",
                            "dst_ip",
                            "dst_name",
                            "dst_source",
                            "dst_port",
                            "length_bytes",
                            "info",
                        ]
                    )
                self.active_files.append(self._log_path)
            except OSError as exc:
                print(
                    f"{ui.RED}"
                    f"{t('file_open_error', path=self._log_path, error=exc)}"
                    f"{ui.RESET}"
                )
                self._log_fp = None

        self._last_flush = time.monotonic()
        return self

    def flush(self) -> None:
        """Flush buffered PCAP and structured log streams to OS buffers."""
        if self._pcap_writer is not None:
            try:
                self._pcap_writer.flush()
            except Exception:
                pass
        if self._log_fp is not None:
            try:
                self._log_fp.flush()
            except OSError:
                pass
        self._since_flush = 0
        self._last_flush = time.monotonic()

    def record(self, raw_packet: Packet, parsed: PacketRecord) -> None:
        """Persist a single packet to enabled sinks with CSV injection defense."""
        if self._pcap_writer is not None:
            try:
                self._pcap_writer.write(raw_packet)
            except Exception:
                pass

        if self._log_fp is not None:
            try:
                if self._is_jsonl:
                    payload = {
                        "timestamp": parsed.timestamp_iso,
                        "protocol": parsed.protocol,
                        "network_layer": parsed.network_layer,
                        "src_ip": parsed.src_ip,
                        "src_name": parsed.src_display,
                        "src_source": parsed.src_source,
                        "src_port": parsed.sport,
                        "dst_ip": parsed.dst_ip,
                        "dst_name": parsed.dst_display,
                        "dst_source": parsed.dst_source,
                        "dst_port": parsed.dport,
                        "length_bytes": parsed.length,
                        "info": parsed.info,
                    }
                    self._log_fp.write(json.dumps(payload, ensure_ascii=False) + "\n")
                elif self._csv_writer is not None:
                    row = [
                        parsed.timestamp_iso,
                        parsed.protocol,
                        parsed.network_layer,
                        parsed.src_ip,
                        parsed.src_display,
                        parsed.src_source,
                        parsed.sport if parsed.sport is not None else "",
                        parsed.dst_ip,
                        parsed.dst_display,
                        parsed.dst_source,
                        parsed.dport if parsed.dport is not None else "",
                        parsed.length,
                        parsed.info,
                    ]
                    self._csv_writer.writerow([sanitize_csv_field(col) for col in row])
            except OSError:
                pass

        self._since_flush += 1
        if (
            self._since_flush >= self.FLUSH_PACKET_INTERVAL
            or (time.monotonic() - self._last_flush) >= self.FLUSH_TIME_INTERVAL
        ):
            self.flush()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.flush()
        if self._pcap_writer is not None:
            try:
                self._pcap_writer.close()
            except Exception:
                pass

        if self._log_fp is not None:
            try:
                self._log_fp.close()
            except OSError:
                pass


def run_capture(
    interface: InterfaceInfo,
    settings: CaptureSettings,
    resolver: Resolver | None = None,
    queue_size: int = 4096,
) -> CaptureStats | None:
    """Capture packets using a non-blocking producer queue and a consumer worker thread."""
    if not has_capture_privileges():
        ui.print_privilege_error(is_windows=(os.name == "nt"))
        return None

    active_resolver = resolver or get_resolver()
    stats = CaptureStats()
    bpf_expr = settings.effective_bpf()

    print(
        f"\n{ui.BLUE}"
        f"{t('capture_starting', iface=interface.display_name)}"
        f"{ui.RESET}"
    )
    print(
        f"{ui.GRAY}"
        f"{t('capture_active_filters', bpf=bpf_expr or t('settings_none'), proto=settings.protocol_filter.upper())}"
        f"{ui.RESET}"
    )

    if settings.max_packets > 0 or settings.duration_limit > 0:
        max_p_str = (
            str(settings.max_packets)
            if settings.max_packets > 0
            else t("settings_unlimited")
        )
        dur_str = (
            f"{settings.duration_limit:g}s"
            if settings.duration_limit > 0
            else t("settings_unlimited")
        )
        print(
            f"{ui.GRAY}"
            f"{t('capture_limits', max_pkts=max_p_str, duration=dur_str)}"
            f"{ui.RESET}"
        )

    pkt_queue: queue.Queue[Packet | None] = queue.Queue(maxsize=max(64, queue_size))
    stop_event = threading.Event()
    dropped_count = 0

    with PacketRecorder(settings.pcap_path, settings.log_path) as recorder:
        if recorder.active_files:
            targets = ", ".join(str(p) for p in recorder.active_files)
            print(f"{ui.GREEN}{t('capture_saving_to', targets=targets)}{ui.RESET}")

        print(f"{ui.CYAN}{'-' * 98}{ui.RESET}")
        start_time = time.monotonic()
        reassembler = TlsStreamReassembler()

        def _consumer_loop() -> None:
            while True:
                try:
                    pkt = pkt_queue.get(timeout=0.25)
                except queue.Empty:
                    recorder.flush()
                    if stop_event.is_set():
                        break
                    continue

                if pkt is None:
                    pkt_queue.task_done()
                    break

                try:
                    if (
                        settings.max_packets > 0
                        and stats.total_packets >= settings.max_packets
                    ):
                        stop_event.set()
                        continue

                    record = dissect_packet(
                        pkt, active_resolver, tls_reassembler=reassembler
                    )
                    if record is None:
                        continue

                    stats.total_packets += 1
                    stats.total_bytes += record.length
                    stats.protocol_counts[record.protocol] += 1
                    if record.dst_host:
                        stats.destination_packets[record.dst_host] += 1
                        stats.destination_bytes[record.dst_host] += record.length

                    recorder.record(pkt, record)
                    print(ui.format_packet_line(record))

                    if stats.total_packets % 100 == 0:
                        print(
                            f"{ui.BLUE}"
                            f"{t('capture_live_stats', count=stats.total_packets, bytes_str=ui.format_bytes(stats.total_bytes), cache=active_resolver.stats_string())}"
                            f"{ui.RESET}"
                        )

                    if (
                        settings.max_packets > 0
                        and stats.total_packets >= settings.max_packets
                    ):
                        stop_event.set()
                finally:
                    pkt_queue.task_done()

        consumer = threading.Thread(
            target=_consumer_loop,
            name="void-eye-consumer",
            daemon=True,
        )
        consumer.start()

        def _enqueue_packet(packet: Packet) -> None:
            nonlocal dropped_count
            if stop_event.is_set():
                return
            try:
                pkt_queue.put_nowait(packet)
            except queue.Full:
                dropped_count += 1

        def _should_stop(_packet: Packet) -> bool:
            return stop_event.is_set()

        sniff_timeout = settings.duration_limit if settings.duration_limit > 0 else None

        sc = _scapy()
        try:
            sc.sniff(
                iface=interface.scapy_iface,
                filter=bpf_expr or None,
                store=False,
                prn=_enqueue_packet,
                stop_filter=_should_stop if settings.max_packets > 0 else None,
                timeout=sniff_timeout,
            )
        except KeyboardInterrupt:
            pass
        except sc.Scapy_Exception as exc:
            stop_event.set()
            consumer.join(timeout=2.0)
            print(f"\n{ui.RED}{t('invalid_bpf', bpf=bpf_expr, error=exc)}{ui.RESET}")
            return None
        except PermissionError:
            stop_event.set()
            consumer.join(timeout=2.0)
            ui.print_privilege_error(is_windows=(os.name == "nt"))
            return None
        except OSError as exc:
            stop_event.set()
            consumer.join(timeout=2.0)
            print(f"\n{ui.RED}{t('sniff_error', error=exc)}{ui.RESET}")
            return None
        finally:
            stop_event.set()
            try:
                pkt_queue.put(None, timeout=1.0)
            except queue.Full:
                pass
            consumer.join(timeout=5.0)
            stats.dropped_packets = dropped_count
            stats.duration_seconds = max(0.0, time.monotonic() - start_time)
            stats.saved_files = list(recorder.active_files)

    ui.print_capture_summary(stats, active_resolver.stats_string())
    return stats
