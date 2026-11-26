"""Tests for TLS/QUIC SNI, DNS dissection, BPF-only filters, exports, i18n, and updater."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import string
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

import i18n
from resolver import Resolver
import sniffer
from tools import update_ranges


def _scapy_layers():
    from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether  # type: ignore[import-untyped]

    return ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether


def _build_client_hello_handshake(
    server_name: str, padding_len: int = 0
) -> bytes:
    """Construct a valid raw TLS 1.2/1.3 Handshake ClientHello message (without record hdr)."""
    host_bytes = server_name.encode("utf-8")
    sni_entry = b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
    sni_ext = (
        struct.pack("!HH", 0x0000, 2 + len(sni_entry))
        + struct.pack("!H", len(sni_entry))
        + sni_entry
    )
    pad_ext = b""
    if padding_len > 0:
        # Place padding extension (0x0015) BEFORE server_name so SNI lands in segment 2+
        pad_ext = struct.pack("!HH", 0x0015, padding_len) + (b"\x00" * padding_len)

    extensions = pad_ext + sni_ext
    body = (
        b"\x03\x03"
        + (b"\x22" * 32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def _build_tls_record(server_name: str, padding_len: int = 0) -> bytes:
    hs = _build_client_hello_handshake(server_name, padding_len=padding_len)
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _build_quic_v1_initial_packet(server_name: str) -> bytes:
    """Construct an authentic RFC 9001 encrypted QUIC v1 Initial packet carrying SNI."""
    hs = _build_client_hello_handshake(server_name)
    # CRYPTO frame (0x06) + offset (0x00) + 2-byte varint length + handshake bytes
    assert len(hs) < 16384
    varint_len = struct.pack("!H", 0x4000 | len(hs))
    plaintext = b"\x06\x00" + varint_len + hs + (b"\x00" * 32)

    dcid = bytes.fromhex("8394c8f03e515708")
    scid = b""
    pn_val = 2
    pn_bytes = struct.pack("!H", pn_val)  # 2-byte packet number (pn_len - 1 == 1)
    unmasked_first = 0xC1  # Long header (1), Fixed (1), Initial (00), Reserved (00), PN len=2 (01)

    rem_len = len(pn_bytes) + len(plaintext) + 16
    rem_varint = struct.pack("!H", 0x4000 | rem_len)
    unmasked_header = (
        bytes([unmasked_first])
        + struct.pack("!I", 0x00000001)
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + b"\x00"  # token_len = 0
        + rem_varint
        + pn_bytes
    )
    pn_offset = len(unmasked_header) - len(pn_bytes)

    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    init_sec = sniffer._hkdf_extract_sha256(salt, dcid)
    cli_sec = sniffer._hkdf_expand_label(init_sec, b"tls13 client in", 32)
    key = sniffer._hkdf_expand_label(cli_sec, b"tls13 quic key", 16)
    iv = sniffer._hkdf_expand_label(cli_sec, b"tls13 quic iv", 12)
    hp_key = sniffer._hkdf_expand_label(cli_sec, b"tls13 quic hp", 16)

    nonce = (int.from_bytes(iv, "big") ^ pn_val).to_bytes(12, "big")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, unmasked_header)

    raw_pkt = bytearray(unmasked_header + ciphertext)
    sample = bytes(raw_pkt[pn_offset + 4 : pn_offset + 20])
    hp_enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = hp_enc.update(sample) + hp_enc.finalize()

    raw_pkt[0] ^= mask[0] & 0x0F
    for idx in range(len(pn_bytes)):
        raw_pkt[pn_offset + idx] ^= mask[1 + idx]
    return bytes(raw_pkt)


def test_extract_tls_sni_valid_truncated_and_malicious() -> None:
    """Single-segment TLS SNI succeeds on valid ClientHello, returns None when truncated or unsafe."""
    valid_rec = _build_tls_record("api.github.com")
    assert sniffer.extract_tls_sni(valid_rec) == "api.github.com"

    # Truncated mid-extension returns None without raising
    assert sniffer.extract_tls_sni(valid_rec[:25]) is None
    assert sniffer.extract_tls_sni(valid_rec[:-4]) is None
    assert sniffer.extract_tls_sni(b"GET / HTTP/1.1\r\n\r\n") is None

    # Escape sequence inside SNI is rejected cleanly
    evil_rec = _build_tls_record("bad\x1b[2J.example.com")
    assert sniffer.extract_tls_sni(evil_rec) is None


def test_multi_segment_tls_client_hello_reassembly(tmp_path: Path) -> None:
    """TlsStreamReassembler reconstructs a ClientHello split across 3 TCP segments."""
    _, _, _, _, IP, TCP, _, Ether = _scapy_layers()
    db_file = tmp_path / "empty.json"
    db_file.write_text("{}", encoding="utf-8")
    resolver = Resolver(db_path=db_file, enable_async_rdns=False)
    reassembler = sniffer.TlsStreamReassembler()

    # Large padding places SNI past byte 1500 so segment 1 & 2 lack SNI
    full_record = _build_tls_record("pq-secure.cloudflare.com", padding_len=1600)
    seg1 = full_record[:700]
    seg2 = full_record[700:1400]
    seg3 = full_record[1400:]

    base_seq = 10_000
    p1 = Ether() / IP(src="192.168.1.5", dst="104.16.1.1") / TCP(sport=51000, dport=443, seq=base_seq) / seg1
    p2 = Ether() / IP(src="192.168.1.5", dst="104.16.1.1") / TCP(sport=51000, dport=443, seq=base_seq + len(seg1)) / seg2
    p3 = Ether() / IP(src="192.168.1.5", dst="104.16.1.1") / TCP(sport=51000, dport=443, seq=base_seq + len(seg1) + len(seg2)) / seg3

    r1 = sniffer.dissect_packet(p1, resolver, tls_reassembler=reassembler)
    r2 = sniffer.dissect_packet(p2, resolver, tls_reassembler=reassembler)
    r3 = sniffer.dissect_packet(p3, resolver, tls_reassembler=reassembler)

    assert r1 is not None and r1.protocol == "TCP"
    assert r2 is not None and r2.protocol == "TCP"
    assert r3 is not None and r3.protocol == "TLS"
    assert r3.dst_display == "~pq-secure.cloudflare.com"
    assert r3.dst_source == "sni"


def test_quic_v1_initial_sni_extraction(tmp_path: Path) -> None:
    """Encrypted QUIC v1 Initial UDP/443 datagram is decrypted and yields SNI."""
    quic_payload = _build_quic_v1_initial_packet("http3.ytimg.com")
    assert sniffer.extract_quic_sni(quic_payload) == "http3.ytimg.com"

    _, _, _, _, IP, _, UDP, Ether = _scapy_layers()
    db_file = tmp_path / "empty.json"
    db_file.write_text("{}", encoding="utf-8")
    resolver = Resolver(db_path=db_file, enable_async_rdns=False)

    pkt = Ether() / IP(src="192.168.1.5", dst="142.250.185.46") / UDP(sport=53000, dport=443) / quic_payload
    pkt.time = 1_700_000_000.5
    rec = sniffer.dissect_packet(pkt, resolver)
    assert rec is not None
    assert rec.protocol == "QUIC"
    assert rec.dst_display == "~http3.ytimg.com"
    assert "QUIC SNI: http3.ytimg.com" in rec.info


def test_extract_dns_info_sanitization_and_real_server_tracking(tmp_path: Path) -> None:
    """DNS dissection sanitizes escape bytes, keeps DNS server visible, and uses packet.time."""
    _, DNS, DNSQR, DNSRR, IP, _, UDP, Ether = _scapy_layers()
    db_file = tmp_path / "db.json"
    db_file.write_text(json.dumps({"known_ips": {"8.8.8.8": "Google DNS"}}), encoding="utf-8")
    resolver = Resolver(db_path=db_file, enable_async_rdns=False)

    # Inject ANSI escape sequence into DNS qname
    raw_pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=55123, dport=53)
        / DNS(id=0x4242, rd=1, qd=DNSQR(qname=b"bad\x1b[31m.example.com."))
    )
    pkt = Ether(bytes(raw_pkt))
    pkt.time = 1_700_000_123.0

    info = sniffer.extract_dns_info(pkt)
    assert info is not None
    assert info.txid == 0x4242
    assert info.is_response is False
    assert info.qname is not None and "\x1b" not in info.qname

    rec = sniffer.dissect_packet(pkt, resolver)
    assert rec is not None
    # DNS server remains visible in dst_display & dst_host; qname goes into info
    assert rec.dst_display == "Google DNS"
    assert rec.dst_host == "Google DNS"
    assert "\x1b" not in rec.info
    assert "Q: bad?[31m.example.com" in rec.info

    # Verify timestamp came from packet.time (2023-11-14), not wall-clock datetime.now()
    assert rec.timestamp_iso.startswith("2023-11-14")

    # Follow-up CNAME + A response
    ans_raw = (
        Ether()
        / IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=55123)
        / DNS(
            id=0x4242,
            qr=1,
            qd=DNSQR(qname=b"www.example.org."),
            an=(
                DNSRR(rrname=b"www.example.org.", type="CNAME", rdata=b"edge.example.org.")
                / DNSRR(rrname=b"edge.example.org.", type="A", rdata="93.184.216.34")
            ),
        )
    )
    ans_info = sniffer.extract_dns_info(Ether(bytes(ans_raw)))
    assert ans_info is not None
    assert ans_info.is_response is True
    assert ("93.184.216.34", "www.example.org") in ans_info.answers


def test_bpf_only_filtering_without_python_duplication() -> None:
    """Protocol filtering relies solely on effective_bpf() with no matches_protocol_filter."""
    assert not hasattr(sniffer, "matches_protocol_filter")

    s = sniffer.CaptureSettings()
    assert s.effective_bpf() == ""

    s.protocol_filter = "tcp"
    assert s.effective_bpf() == "tcp"

    s.bpf_filter = "host 1.1.1.1"
    assert s.effective_bpf() == "(host 1.1.1.1) and (tcp)"

    s.protocol_filter = "icmp"
    assert s.effective_bpf() == "(host 1.1.1.1) and (icmp or icmp6)"


def test_packet_recorder_jsonl_and_csv_injection_protection(tmp_path: Path) -> None:
    """PacketRecorder streams JSONL lines and escapes dangerous formula cells in CSV."""
    ARP, _, _, _, _, _, _, Ether = _scapy_layers()
    pcap_out = tmp_path / "cap.pcap"
    jsonl_out = tmp_path / "cap.jsonl"
    csv_out = tmp_path / "cap.csv"

    dummy_pkt = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2")
    forged_record = sniffer.PacketRecord(
        timestamp_iso="2026-01-01T00:00:00.000",
        timestamp_short="00:00:00",
        protocol="DNS",
        network_layer="IPv4",
        src_ip="192.168.1.10",
        src_display="=CMD()",
        src_source="dns",
        sport=53000,
        dst_ip="8.8.8.8",
        dst_display="+SUM(1,2)",
        dst_host="Google DNS",
        dst_source="known",
        dport=53,
        length=74,
        info="@IMPORTXML()",
    )

    with sniffer.PacketRecorder(pcap_out, jsonl_out) as rec_jsonl:
        rec_jsonl.record(dummy_pkt, forged_record)
        rec_jsonl.record(dummy_pkt, forged_record)

    lines = jsonl_out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    parsed_line = json.loads(lines[0])
    assert parsed_line["src_source"] == "dns"
    assert parsed_line["dst_source"] == "known"
    assert pcap_out.stat().st_size > 24

    with sniffer.PacketRecorder(None, csv_out) as rec_csv:
        rec_csv.record(dummy_pkt, forged_record)

    with csv_out.open("r", encoding="utf-8", newline="") as fp:
        rows = list(csv.reader(fp))
    assert len(rows) == 2
    data_row = rows[1]
    assert data_row[4] == "'=CMD()"
    assert data_row[8] == "'+SUM(1,2)"
    assert data_row[12] == "'@IMPORTXML()"


def test_i18n_key_and_placeholder_parity_across_languages() -> None:
    """Every translation key and format {placeholder} matches across en, ar, and tr."""
    formatter = string.Formatter()
    base_keys = set(i18n.TRANSLATIONS["en"].keys())

    for lang_code, table in i18n.TRANSLATIONS.items():
        assert set(table.keys()) == base_keys, f"Key mismatch in language '{lang_code}'"
        for key, template in table.items():
            en_placeholders = {
                fname
                for _, fname, _, _ in formatter.parse(i18n.TRANSLATIONS["en"][key])
                if fname is not None
            }
            lang_placeholders = {
                fname
                for _, fname, _, _ in formatter.parse(template)
                if fname is not None
            }
            assert lang_placeholders == en_placeholders, (
                f"Placeholder mismatch for key '{key}' in '{lang_code}': "
                f"{lang_placeholders} != {en_placeholders}"
            )


def test_config_user_dir_and_unwritable_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Config defaults show legal notice on first run and degrade safely when unwritable."""
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    cfg_path = i18n.get_default_config_path()
    assert cfg_path.parent.name == "void_eye"
    assert not cfg_path.exists()

    # Fresh user gets default config with legal_notice_shown == False
    fresh = i18n.load_config(cfg_path)
    assert fresh.language == "en"
    assert fresh.legal_notice_shown is False

    # Saving and reloading persists values
    fresh.language = "tr"
    fresh.legal_notice_shown = True
    assert i18n.save_config(fresh, cfg_path) is True
    reloaded = i18n.load_config(cfg_path)
    assert reloaded.language == "tr"
    assert reloaded.legal_notice_shown is True

    # Unwritable path (parent is an existing regular file!) returns False without raising
    blocker_file = tmp_path / "occupied_file"
    blocker_file.write_text("not a dir", encoding="utf-8")
    unwritable_target = blocker_file / "void_eye" / "config.json"
    assert i18n.save_config(fresh, unwritable_target) is False


def test_update_ranges_validation_and_offline_safety(tmp_path: Path) -> None:
    """update_ranges rejects unsafe CIDRs and preserves known_ips.json when offline."""
    assert update_ranges.validate_public_cidr("0.0.0.0/0") is None
    assert update_ranges.validate_public_cidr("192.168.0.0/16") is None
    assert update_ranges.validate_public_cidr("127.0.0.0/8") is None
    assert str(update_ranges.validate_public_cidr("104.16.0.0/13")) == "104.16.0.0/13"

    db_copy = tmp_path / "known_ips.json"
    original_payload = {
        "known_ips": {"8.8.8.8": "Google DNS"},
        "known_ranges": {"192.30.252.0/22": "GitHub", "104.16.0.0/13": "Cloudflare"},
        "domain_keywords": {"github": "GitHub"},
    }
    db_copy.write_text(json.dumps(original_payload), encoding="utf-8")

    # Pointing offline_dir to an empty folder simulates total feed unavailability
    empty_feeds = tmp_path / "empty_feeds"
    empty_feeds.mkdir()
    rc = update_ranges.update_database(db_copy, offline_dir=empty_feeds)
    assert rc == 0
    assert json.loads(db_copy.read_text(encoding="utf-8")) == original_payload

    # Local offline feed merge refreshes Cloudflare while keeping curated GitHub
    (empty_feeds / "ips-v4").write_text("173.245.48.0/20\n0.0.0.0/0\n", encoding="utf-8")
    (empty_feeds / "ips-v6").write_text("2606:4700::/32\n", encoding="utf-8")
    rc2 = update_ranges.update_database(db_copy, offline_dir=empty_feeds)
    assert rc2 == 0
    merged = json.loads(db_copy.read_text(encoding="utf-8"))["known_ranges"]
    assert merged["192.30.252.0/22"] == "GitHub"
    assert merged["173.245.48.0/20"] == "Cloudflare"
    assert "0.0.0.0/0" not in merged
