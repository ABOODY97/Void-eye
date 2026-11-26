"""Packet sniffing, protocol dissection (IPv4/IPv6/ARP/DNS/TLS), and file export."""

from __future__ import annotations

from collections import Counter
import csv
import ctypes
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import time
from typing import Any, TextIO

from scapy.all import (  # type: ignore[import-untyped]
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    IPv6,
    PcapWriter,
    Packet,
    Scapy_Exception,
    conf,
    sniff,
)

from i18n import t
from resolver import Resolver, get_resolver
import ui

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
    """Mutable capture filter and export configuration."""

    bpf_filter: str = ""
    protocol_filter: str = "all"
    pcap_path: Path | None = None
    log_path: Path | None = None

    def reset(self) -> None:
        """Restore default capture settings."""
        self.bpf_filter = ""
        self.protocol_filter = "all"
        self.pcap_path = None
        self.log_path = None

    def effective_bpf(self) -> str:
        """Combine user BPF expression with the selected protocol filter."""
        proto_expr = PROTOCOL_BPF_MAP.get(self.protocol_filter.lower(), "")
        custom = self.bpf_filter.strip()
        if custom and proto_expr:
            return f"({custom}) and ({proto_expr})"
        return custom or proto_expr


@dataclass(frozen=True)
class PacketRecord:
    """Normalized dissected packet information for display and export."""

    timestamp_iso: str
    timestamp_short: str
    protocol: str
    network_layer: str
    src_ip: str
    src_display: str
    sport: int | None
    dst_ip: str
    dst_display: str
    dport: int | None
    length: int
    info: str


@dataclass
class CaptureStats:
    """Aggregated traffic metrics collected during a capture session."""

    total_packets: int = 0
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
        iface_values = list(conf.ifaces.values())
    except Exception:
        return results

    for iface in iface_values:
        name = str(getattr(iface, "name", "") or "").strip()
        description = str(getattr(iface, "description", "") or "").strip()
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
                    # Prefer global IPv6 over link-local if available.
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


def extract_tls_sni(payload: bytes) -> str | None:
    """Extract Server Name Indication (SNI) from a raw TLS ClientHello payload.

    Bounds-checked RFC 5246 / RFC 6066 parser requiring zero Scapy TLS overhead.
    """
    data_len = len(payload)
    # TLS record header (5 bytes) + Handshake header (4 bytes) + min ClientHello (38 bytes)
    if data_len < 47:
        return None

    # ContentType 0x16 = Handshake; major version 0x03 (SSL 3.0 / TLS 1.0-1.3)
    if payload[0] != 0x16 or payload[1] != 0x03:
        return None

    record_len = struct.unpack("!H", payload[3:5])[0]
    end_record = min(data_len, 5 + record_len)

    # HandshakeType 0x01 = ClientHello
    if payload[5] != 0x01:
        return None

    handshake_len = int.from_bytes(payload[6:9], "big")
    end_hs = min(end_record, 9 + handshake_len)

    # Skip client_version (2B) + random (32B)
    pos = 9 + 2 + 32
    if pos + 1 > end_hs:
        return None

    # Skip session_id
    session_id_len = payload[pos]
    pos += 1 + session_id_len
    if pos + 2 > end_hs:
        return None

    # Skip cipher_suites
    cipher_suites_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2 + cipher_suites_len
    if pos + 1 > end_hs:
        return None

    # Skip compression_methods
    comp_methods_len = payload[pos]
    pos += 1 + comp_methods_len
    if pos + 2 > end_hs:
        return None

    # Parse extensions
    extensions_len = struct.unpack("!H", payload[pos : pos + 2])[0]
    pos += 2
    end_ext = min(end_hs, pos + extensions_len)

    while pos + 4 <= end_ext:
        ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
        pos += 4
        if pos + ext_len > end_ext:
            return None

        if ext_type == 0x0000 and ext_len >= 5:  # server_name extension
            list_len = struct.unpack("!H", payload[pos : pos + 2])[0]
            sni_pos = pos + 2
            sni_end = min(pos + ext_len, sni_pos + list_len)
            while sni_pos + 3 <= sni_end:
                name_type = payload[sni_pos]
                name_len = struct.unpack("!H", payload[sni_pos + 1 : sni_pos + 3])[0]
                sni_pos += 3
                if sni_pos + name_len > sni_end:
                    return None
                if name_type == 0x00 and name_len > 0:  # host_name
                    raw_host = payload[sni_pos : sni_pos + name_len]
                    try:
                        host = raw_host.decode("ascii").strip().rstrip(".").lower()
                        if host and "." in host:
                            return host
                    except UnicodeDecodeError:
                        return None
                sni_pos += name_len
            return None

        pos += ext_len

    return None


def _decode_dns_name(raw_name: Any) -> str:
    """Normalize a Scapy DNS domain field (bytes or str) into a clean hostname."""
    if isinstance(raw_name, bytes):
        text = raw_name.decode("utf-8", errors="replace")
    else:
        text = str(raw_name or "")
    return text.strip().rstrip(".").lower()


def extract_dns_info(packet: Packet) -> tuple[str | None, bool, list[tuple[str, str]]]:
    """Extract (qname, is_response, [(resolved_ip, domain)]) from a DNS packet."""
    if not packet.haslayer(DNS):
        return None, False, []

    dns_layer = packet[DNS]
    is_response = bool(getattr(dns_layer, "qr", 0))
    qname: str | None = None

    if packet.haslayer(DNSQR):
        candidate = _decode_dns_name(getattr(packet[DNSQR], "qname", b""))
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
            while isinstance(cur, DNSRR):
                answers.append(cur)
                cur = cur.payload if isinstance(cur.payload, DNSRR) else None

        cname_map: dict[str, str] = {}
        ip_records: list[tuple[str, str]] = []

        for answer in answers:
            if not isinstance(answer, DNSRR):
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

    return qname, is_response, mappings


def matches_protocol_filter(record: PacketRecord, proto_filter: str) -> bool:
    """Secondary Python-level protocol filter check matching CaptureSettings."""
    pf = proto_filter.lower()
    if pf == "all":
        return True
    if pf == "ipv6":
        return record.network_layer == "IPv6"
    if pf == "icmp":
        return record.protocol in {"ICMP", "ICMPv6"}
    if pf == "dns":
        return record.protocol == "DNS"
    if pf == "tcp":
        return record.protocol in {"TCP", "TLS"} or (
            record.protocol == "DNS" and record.sport is not None
        )
    if pf == "udp":
        return record.protocol == "UDP" or record.protocol == "DNS"
    if pf == "arp":
        return record.protocol == "ARP"
    return True


def dissect_packet(packet: Packet, resolver: Resolver) -> PacketRecord | None:
    """Dissect IPv4, IPv6, or ARP packet into a normalized PacketRecord."""
    now = datetime.now()
    ts_iso = now.isoformat(timespec="milliseconds")
    ts_short = now.strftime("%H:%M:%S")
    pkt_len = len(packet)

    # 1. ARP packets
    if packet.haslayer(ARP):
        arp = packet[ARP]
        src_ip = str(getattr(arp, "psrc", ""))
        dst_ip = str(getattr(arp, "pdst", ""))
        src_disp = resolver.resolve(src_ip) if src_ip else str(getattr(arp, "hwsrc", ""))
        dst_disp = resolver.resolve(dst_ip) if dst_ip else str(getattr(arp, "hwdst", ""))
        op = int(getattr(arp, "op", 0))
        if op == 1:
            info = f"Who has {dst_ip}? Tell {src_ip}"
        elif op == 2:
            hwsrc = getattr(arp, "hwsrc", "")
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
            sport=None,
            dst_ip=dst_ip,
            dst_display=dst_disp,
            dport=None,
            length=pkt_len,
            info=info,
        )

    # 2. IPv4 / IPv6 packets
    if packet.haslayer(IP):
        net_layer = "IPv4"
        src_ip = str(packet[IP].src)
        dst_ip = str(packet[IP].dst)
        ip_proto = int(getattr(packet[IP], "proto", 0))
    elif packet.haslayer(IPv6):
        net_layer = "IPv6"
        src_ip = str(packet[IPv6].src)
        dst_ip = str(packet[IPv6].dst)
        ip_proto = int(getattr(packet[IPv6], "nh", 0))
    else:
        return None

    # Passively inspect DNS before resolving IPs so DNS answers enrich cache first.
    qname, is_dns_resp, dns_mappings = extract_dns_info(packet)
    for mapped_ip, mapped_domain in dns_mappings:
        resolver.learn_dns_mapping(mapped_ip, mapped_domain)

    src_disp = resolver.resolve(src_ip)
    dst_disp = resolver.resolve(dst_ip)
    protocol = net_layer
    sport: int | None = None
    dport: int | None = None
    info = ""

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        sport = int(tcp.sport)
        dport = int(tcp.dport)
        s_srv = get_service_name(sport, "tcp")
        d_srv = get_service_name(dport, "tcp")
        protocol = "TCP"
        info = f"{s_srv} -> {d_srv}"

        raw_payload = bytes(tcp.payload)
        sni = extract_tls_sni(raw_payload) if raw_payload else None
        if sni:
            protocol = "TLS"
            resolver.learn_dns_mapping(dst_ip, sni)
            dst_disp = sni
            info = f"{s_srv} -> {d_srv} [SNI: {sni}]"
        elif qname:
            protocol = "DNS"
            if not is_dns_resp:
                dst_disp = qname
                info = f"{s_srv} -> {d_srv} [Q: {qname}]"
            else:
                info = f"{s_srv} -> {d_srv} [A: {qname}]"

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        sport = int(udp.sport)
        dport = int(udp.dport)
        s_srv = get_service_name(sport, "udp")
        d_srv = get_service_name(dport, "udp")
        protocol = "UDP"
        info = f"{s_srv} -> {d_srv}"

        if qname:
            protocol = "DNS"
            if not is_dns_resp:
                dst_disp = qname
                info = f"{s_srv} -> {d_srv} [Q: {qname}]"
            else:
                src_disp = qname
                info = f"{s_srv} -> {d_srv} [Ans: {qname}]"

    elif packet.haslayer(ICMP):
        icmp_type = int(getattr(packet[ICMP], "type", -1))
        icmp_code = int(getattr(packet[ICMP], "code", 0))
        type_desc = ICMPV4_TYPES.get(icmp_type, f"Type {icmp_type}")
        protocol = "ICMP"
        info = f"{type_desc} (code={icmp_code})"

    elif ip_proto == 58:  # ICMPv6
        protocol = "ICMPv6"
        icmp6_layer = packet[IPv6].payload
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
        sport=sport,
        dst_ip=dst_ip,
        dst_display=dst_disp,
        dport=dport,
        length=pkt_len,
        info=info,
    )


class PacketRecorder:
    """Streaming context manager writing captured packets to .pcap and .csv/.json."""

    def __init__(self, pcap_path: Path | None, log_path: Path | None) -> None:
        self._pcap_path = pcap_path
        self._log_path = log_path
        self._pcap_writer: PcapWriter | None = None
        self._log_fp: TextIO | None = None
        self._csv_writer: Any = None
        self._is_json = False
        self._first_json_item = True
        self.active_files: list[Path] = []

    def __enter__(self) -> PacketRecorder:
        if self._pcap_path is not None:
            try:
                self._pcap_path.parent.mkdir(parents=True, exist_ok=True)
                self._pcap_writer = PcapWriter(
                    str(self._pcap_path), append=False, sync=True
                )
                self.active_files.append(self._pcap_path)
            except (OSError, Scapy_Exception) as exc:
                print(
                    f"{ui.RED}"
                    f"{t('file_open_error', path=self._pcap_path, error=exc)}"
                    f"{ui.RESET}"
                )
                self._pcap_writer = None

        if self._log_path is not None:
            try:
                self._log_path.parent.mkdir(parents=True, exist_ok=True)
                self._is_json = self._log_path.suffix.lower() == ".json"
                self._log_fp = self._log_path.open("w", encoding="utf-8", newline="")
                if self._is_json:
                    self._log_fp.write("[\n")
                else:
                    self._csv_writer = csv.writer(self._log_fp)
                    self._csv_writer.writerow(
                        [
                            "timestamp",
                            "protocol",
                            "network_layer",
                            "src_ip",
                            "src_name",
                            "src_port",
                            "dst_ip",
                            "dst_name",
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

        return self

    def record(self, raw_packet: Packet, parsed: PacketRecord) -> None:
        """Persist a single packet to any enabled output sinks."""
        if self._pcap_writer is not None:
            try:
                self._pcap_writer.write(raw_packet)
            except (OSError, Scapy_Exception):
                pass

        if self._log_fp is not None:
            try:
                if self._is_json:
                    prefix = "  " if self._first_json_item else ",\n  "
                    self._first_json_item = False
                    payload = {
                        "timestamp": parsed.timestamp_iso,
                        "protocol": parsed.protocol,
                        "network_layer": parsed.network_layer,
                        "src_ip": parsed.src_ip,
                        "src_name": parsed.src_display,
                        "src_port": parsed.sport,
                        "dst_ip": parsed.dst_ip,
                        "dst_name": parsed.dst_display,
                        "dst_port": parsed.dport,
                        "length_bytes": parsed.length,
                        "info": parsed.info,
                    }
                    self._log_fp.write(prefix + json.dumps(payload, ensure_ascii=False))
                elif self._csv_writer is not None:
                    self._csv_writer.writerow(
                        [
                            parsed.timestamp_iso,
                            parsed.protocol,
                            parsed.network_layer,
                            parsed.src_ip,
                            parsed.src_display,
                            parsed.sport or "",
                            parsed.dst_ip,
                            parsed.dst_display,
                            parsed.dport or "",
                            parsed.length,
                            parsed.info,
                        ]
                    )
            except OSError:
                pass

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._pcap_writer is not None:
            try:
                self._pcap_writer.close()
            except Exception:
                pass

        if self._log_fp is not None:
            try:
                if self._is_json:
                    self._log_fp.write("\n]\n")
                self._log_fp.flush()
                self._log_fp.close()
            except OSError:
                pass


def run_capture(
    interface: InterfaceInfo,
    settings: CaptureSettings,
    resolver: Resolver | None = None,
) -> CaptureStats | None:
    """Start live packet capture on *interface* until stopped with Ctrl+C."""
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

    with PacketRecorder(settings.pcap_path, settings.log_path) as recorder:
        if recorder.active_files:
            targets = ", ".join(str(p) for p in recorder.active_files)
            print(f"{ui.GREEN}{t('capture_saving_to', targets=targets)}{ui.RESET}")

        print(f"{ui.CYAN}{'-' * 98}{ui.RESET}")
        start_time = time.monotonic()

        def _handle_packet(packet: Packet) -> None:
            record = dissect_packet(packet, active_resolver)
            if record is None:
                return
            if not matches_protocol_filter(record, settings.protocol_filter):
                return

            stats.total_packets += 1
            stats.total_bytes += record.length
            stats.protocol_counts[record.protocol] += 1
            if record.dst_display:
                stats.destination_packets[record.dst_display] += 1
                stats.destination_bytes[record.dst_display] += record.length

            recorder.record(packet, record)
            print(ui.format_packet_line(record))

            if stats.total_packets % 100 == 0:
                print(
                    f"{ui.BLUE}"
                    f"{t('capture_live_stats', count=stats.total_packets, bytes_str=ui.format_bytes(stats.total_bytes), cache=active_resolver.stats_string())}"
                    f"{ui.RESET}"
                )

        try:
            sniff(
                iface=interface.scapy_iface,
                filter=bpf_expr or None,
                store=False,
                prn=_handle_packet,
            )
        except KeyboardInterrupt:
            pass
        except Scapy_Exception as exc:
            print(f"\n{ui.RED}{t('invalid_bpf', bpf=bpf_expr, error=exc)}{ui.RESET}")
            return None
        except PermissionError:
            ui.print_privilege_error(is_windows=(os.name == "nt"))
            return None
        except OSError as exc:
            print(f"\n{ui.RED}{t('sniff_error', error=exc)}{ui.RESET}")
            return None
        finally:
            stats.duration_seconds = max(0.0, time.monotonic() - start_time)
            stats.saved_files = list(recorder.active_files)

    ui.print_capture_summary(stats, active_resolver.stats_string())
    return stats
