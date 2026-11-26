"""Terminal UI components: Colorama palette, banner, aligned tables, and menus."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from colorama import Fore, Style, init

from i18n import (
    SUPPORTED_LANGUAGES,
    AppConfig,
    get_language,
    is_bidi_enabled,
    save_config,
    set_bidi_enabled,
    set_language,
    t,
)

if TYPE_CHECKING:
    from sniffer import CaptureSettings, CaptureStats, InterfaceInfo, PacketRecord

# Color palette (Colorama equivalents preserving the original visual look)
GREEN = Fore.LIGHTGREEN_EX
BLUE = Fore.LIGHTBLUE_EX
YELLOW = Fore.LIGHTYELLOW_EX
CYAN = Fore.LIGHTCYAN_EX
RED = Fore.LIGHTRED_EX
GRAY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL

BANNER = (
    "██╗   ██╗ ██████╗ ██╗██████╗     ███████╗██╗   ██╗███████╗\n"
    "██║   ██║██╔═══██╗██║██╔══██╗    ██╔════╝╚██╗ ██╔╝██╔════╝\n"
    "██║   ██║██║   ██║██║██║  ██║    █████╗   ╚████╔╝ █████╗\n"
    "╚██╗ ██╔╝██║   ██║██║██║  ██║    ██╔══╝    ╚██╔╝  ██╔══╝\n"
    " ╚████╔╝ ╚██████╔╝██║██████╔╝    ███████╗   ██║   ███████╗\n"
    "  ╚═══╝   ╚═════╝ ╚═╝╚═════╝     ╚══════╝   ╚═╝   ╚══════╝\n"
    "        MINI WIRESHARK - FROM ABOODY"
)

ALLOWED_PROTOCOLS: tuple[str, ...] = (
    "all",
    "tcp",
    "udp",
    "icmp",
    "dns",
    "arp",
    "ipv6",
)


def init_colors() -> None:
    """Initialize Colorama with autoreset enabled."""
    init(autoreset=True)


def fit_column(text: str, width: int, align: str = "left") -> str:
    """Truncate and pad plain text BEFORE wrapping in ANSI color sequences."""
    if width <= 0:
        return ""
    if len(text) > width:
        if width <= 3:
            truncated = text[:width]
        else:
            truncated = f"{text[: width - 3]}..."
    else:
        truncated = text

    if align == "right":
        return f"{truncated:>{width}}"
    return f"{truncated:<{width}}"


def format_bytes(num_bytes: int) -> str:
    """Convert raw byte count into a compact human-readable string."""
    value = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{num_bytes} B"


def safe_input(prompt_text: str, color: str = BLUE) -> str | None:
    """Prompt user with explicit RESET; return None on Ctrl+C or EOF."""
    try:
        return input(f"{color}{prompt_text}{RESET}")
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def print_banner() -> None:
    """Print the centered VOID EYE ASCII banner and subtitle."""
    print(f"\n{CYAN}{BANNER}{RESET}\n")


def show_legal_notice_once(config: AppConfig, interactive: bool = True) -> bool:
    """Display the legal/ethical disclaimer once on first launch for new users.

    Returns False only if the user aborts via Ctrl+C/EOF at acknowledgement.
    """
    if config.legal_notice_shown:
        return True

    border = "=" * 68
    print(f"\n{YELLOW}{border}{RESET}")
    print(f"{RED}  [!] {t('legal_title')}{RESET}")
    print(f"{YELLOW}  {t('legal_body_1')}{RESET}")
    print(f"{YELLOW}  {t('legal_body_2')}{RESET}")
    print(f"{YELLOW}{border}{RESET}")

    if interactive:
        ack = safe_input(f"  {t('legal_continue')}", color=CYAN)
        if ack is None:
            return False

    config.legal_notice_shown = True
    save_config(config)
    return True


def print_privilege_error(is_windows: bool) -> None:
    """Display a clear translated privilege/driver instruction message."""
    print(f"\n{RED}{t('priv_error_title')}{RESET}")
    hint_key = "priv_error_windows" if is_windows else "priv_error_unix"
    print(f"{YELLOW}{t(hint_key)}{RESET}\n")


def print_interfaces_table(
    interfaces: list[InterfaceInfo], *, include_back_option: bool = False
) -> None:
    """Render the formatted table of active network interfaces."""
    if not interfaces:
        print(f"\n{RED}{t('ifaces_none')}{RESET}")
        return

    line = "=" * 74
    print(f"\n{CYAN}{line}{RESET}")
    print(f"{CYAN}{t('ifaces_title')}{RESET}")
    print(f"{CYAN}{line}{RESET}")

    for idx, iface in enumerate(interfaces, start=1):
        idx_col = fit_column(f"[{idx}]", 5)
        name_col = fit_column(iface.display_name, 36)
        ipv4_col = fit_column(iface.ipv4 or "-", 16)
        ipv6_text = f"  {GRAY}({iface.ipv6}){RESET}" if iface.ipv6 else ""
        ip_color = GREEN if iface.ipv4 else CYAN
        print(
            f"  {YELLOW}{idx_col}{RESET} "
            f"{BLUE}{name_col}{RESET} "
            f"{ip_color}{ipv4_col}{RESET}{ipv6_text}"
        )

    if include_back_option:
        print(f"  {GRAY}{t('ifaces_back')}{RESET}")
    print(f"{CYAN}{line}{RESET}")


def prompt_main_menu() -> int | None:
    """Render the main menu and return the chosen option (1-4), or None on abort."""
    print_banner()

    opt1 = fit_column(t("menu_opt_1_label"), 30)
    opt2 = fit_column(t("menu_opt_2_label"), 30)
    opt3 = t("menu_opt_3_label")
    opt4 = t("menu_opt_4_label")

    print(f"{YELLOW}[1]{RESET} {BLUE}{opt1}{RESET}{GRAY}{t('menu_opt_1_desc')}{RESET}")
    print(f"{YELLOW}[2]{RESET} {BLUE}{opt2}{RESET}{GRAY}{t('menu_opt_2_desc')}{RESET}")
    print(f"{YELLOW}[3]{RESET} {BLUE}{opt3}{RESET}")
    print(f"{YELLOW}[4]{RESET} {BLUE}{opt4}{RESET}\n")

    while True:
        raw = safe_input(t("menu_prompt"), color=BLUE)
        if raw is None:
            return None
        stripped = raw.strip()
        try:
            choice = int(stripped)
        except ValueError:
            print(f"{RED}{t('invalid_number')}{RESET}")
            continue

        if 1 <= choice <= 4:
            return choice
        print(f"{RED}{t('invalid_choice_range', min_val=1, max_val=4)}{RESET}")


def prompt_interface_menu(interfaces: list[InterfaceInfo]) -> InterfaceInfo | None:
    """Display discovered interfaces and return the selected InterfaceInfo."""
    if not interfaces:
        print(f"\n{RED}{t('ifaces_none')}{RESET}")
        return None

    print_interfaces_table(interfaces, include_back_option=True)

    while True:
        raw = safe_input(t("ifaces_prompt", count=len(interfaces)), color=BLUE)
        if raw is None:
            return None
        try:
            choice = int(raw.strip())
        except ValueError:
            print(f"{RED}{t('invalid_number')}{RESET}")
            continue

        if choice == 0:
            return None
        if 1 <= choice <= len(interfaces):
            selected = interfaces[choice - 1]
            print(f"{GREEN}{t('iface_selected', iface=selected.display_name)}{RESET}")
            return selected
        print(
            f"{RED}{t('invalid_choice_range', min_val=0, max_val=len(interfaces))}{RESET}"
        )


def run_settings_menu(settings: CaptureSettings, config: AppConfig) -> None:
    """Interactive submenu to configure BPF, protocol filter, output files, and BiDi."""
    while True:
        line = "=" * 68
        bpf_val = settings.bpf_filter or t("settings_none")
        proto_val = (
            t("settings_all")
            if settings.protocol_filter == "all"
            else settings.protocol_filter.upper()
        )
        pcap_val = str(settings.pcap_path) if settings.pcap_path else t("settings_none")
        log_val = str(settings.log_path) if settings.log_path else t("settings_none")
        bidi_val = t("settings_on") if is_bidi_enabled() else t("settings_off")

        print(f"\n{CYAN}{line}{RESET}")
        print(f"{CYAN}{t('settings_title')}{RESET}")
        print(f"{CYAN}{line}{RESET}")
        print(
            f"  {YELLOW}[1]{RESET} {BLUE}{fit_column(t('settings_bpf'), 26)}{RESET}: "
            f"{GREEN}{bpf_val}{RESET}"
        )
        print(
            f"  {YELLOW}[2]{RESET} {BLUE}{fit_column(t('settings_proto'), 26)}{RESET}: "
            f"{GREEN}{proto_val}{RESET}"
        )
        print(
            f"  {YELLOW}[3]{RESET} {BLUE}{fit_column(t('settings_pcap'), 26)}{RESET}: "
            f"{GREEN}{pcap_val}{RESET}"
        )
        print(
            f"  {YELLOW}[4]{RESET} {BLUE}{fit_column(t('settings_log'), 26)}{RESET}: "
            f"{GREEN}{log_val}{RESET}"
        )
        print(
            f"  {YELLOW}[5]{RESET} {BLUE}{fit_column(t('settings_bidi'), 26)}{RESET}: "
            f"{GREEN}{bidi_val}{RESET}"
        )
        print(f"  {YELLOW}[6]{RESET} {BLUE}{t('settings_reset')}{RESET}")
        print(f"  {GRAY}[0] {t('settings_back')}{RESET}")
        print(f"{CYAN}{line}{RESET}")

        raw = safe_input(t("settings_prompt"), color=BLUE)
        if raw is None:
            return
        try:
            choice = int(raw.strip())
        except ValueError:
            print(f"{RED}{t('invalid_number')}{RESET}")
            continue

        if choice == 0:
            return
        if choice == 1:
            val = safe_input(t("prompt_bpf"), color=BLUE)
            if val is not None:
                settings.bpf_filter = val.strip()
                print(f"{GREEN}{t('settings_updated')}{RESET}")
        elif choice == 2:
            val = safe_input(t("prompt_proto"), color=BLUE)
            if val is not None:
                proto = val.strip().lower() or "all"
                if proto in ALLOWED_PROTOCOLS:
                    settings.protocol_filter = proto
                    print(f"{GREEN}{t('settings_updated')}{RESET}")
                else:
                    print(f"{RED}{t('invalid_proto', proto=val.strip())}{RESET}")
        elif choice == 3:
            val = safe_input(t("prompt_pcap"), color=BLUE)
            if val is not None:
                cleaned = val.strip().strip('"')
                if not cleaned:
                    settings.pcap_path = None
                else:
                    path = Path(cleaned)
                    if path.suffix.lower() not in {".pcap", ".pcapng"}:
                        path = path.with_suffix(".pcap")
                    settings.pcap_path = path
                print(f"{GREEN}{t('settings_updated')}{RESET}")
        elif choice == 4:
            val = safe_input(t("prompt_log"), color=BLUE)
            if val is not None:
                cleaned = val.strip().strip('"')
                if not cleaned:
                    settings.log_path = None
                else:
                    path = Path(cleaned)
                    ext = path.suffix.lower()
                    if ext == ".json":
                        path = path.with_suffix(".jsonl")
                        print(f"{YELLOW}{t('log_ext_adjusted', path=path)}{RESET}")
                    elif ext not in {".csv", ".jsonl"}:
                        path = path.with_suffix(".csv")
                        print(f"{YELLOW}{t('log_ext_adjusted', path=path)}{RESET}")
                    settings.log_path = path
                print(f"{GREEN}{t('settings_updated')}{RESET}")
        elif choice == 5:
            new_state = not is_bidi_enabled()
            set_bidi_enabled(new_state)
            config.bidi_enabled = new_state
            save_config(config)
            print(f"{GREEN}{t('settings_updated')}{RESET}")
        elif choice == 6:
            settings.reset()
            print(f"{GREEN}{t('settings_was_reset')}{RESET}")
        else:
            print(f"{RED}{t('invalid_choice_range', min_val=0, max_val=6)}{RESET}")


def run_language_menu(config: AppConfig) -> None:
    """Interactive menu to switch UI language and persist in user config dir."""
    codes = list(SUPPORTED_LANGUAGES.keys())
    line = "=" * 50
    print(f"\n{CYAN}{line}{RESET}")
    print(f"{CYAN}{t('lang_title')}{RESET}")
    print(f"{CYAN}{line}{RESET}")

    current = get_language()
    for idx, code in enumerate(codes, start=1):
        label = SUPPORTED_LANGUAGES[code]
        if code == "ar" and is_bidi_enabled():
            from arabic_tools import fix_ar

            label = fix_ar(label, enabled=True)
        marker = f" {GREEN}*{RESET}" if code == current else ""
        print(f"  {YELLOW}[{idx}]{RESET} {BLUE}{label}{RESET} ({code}){marker}")

    print(f"  {GRAY}{t('lang_back')}{RESET}")
    print(f"{CYAN}{line}{RESET}")

    while True:
        raw = safe_input(t("lang_prompt", count=len(codes)), color=BLUE)
        if raw is None:
            return
        try:
            choice = int(raw.strip())
        except ValueError:
            print(f"{RED}{t('invalid_number')}{RESET}")
            continue

        if choice == 0:
            return
        if 1 <= choice <= len(codes):
            chosen_code = codes[choice - 1]
            set_language(chosen_code)
            config.language = chosen_code
            save_config(config)
            print(
                f"{GREEN}"
                f"{t('lang_changed', lang_name=SUPPORTED_LANGUAGES[chosen_code])}"
                f"{RESET}"
            )
            return
        print(f"{RED}{t('invalid_choice_range', min_val=0, max_val=len(codes))}{RESET}")


def _proto_color(protocol: str) -> str:
    """Select display color for a given protocol badge."""
    upper = protocol.upper()
    if upper in {"TCP", "TLS"}:
        return GREEN
    if upper in {"UDP", "DNS", "QUIC"}:
        return CYAN
    if upper in {"ICMP", "ICMPV6", "ARP"}:
        return YELLOW
    return BLUE


def _style_host_column(padded_col: str) -> str:
    """Highlight leading '~' unauthenticated marker in GRAY without altering width."""
    if padded_col.startswith("~"):
        return f"{GRAY}~{RESET}{padded_col[1:]}"
    return padded_col


def format_packet_line(record: PacketRecord) -> str:
    """Format a captured packet into a strictly column-aligned colored terminal line."""
    ts_col = fit_column(record.timestamp_short, 8)
    proto_col = fit_column(record.protocol, 6)
    size_col = fit_column(f"{record.length}B", 7, align="right")
    src_col = _style_host_column(fit_column(record.src_display, 26))
    dst_col = _style_host_column(fit_column(record.dst_display, 26))

    p_color = _proto_color(record.protocol)
    details_part = f" {GRAY}|{RESET} {record.info}" if record.info else ""

    return (
        f"{GRAY}{ts_col}{RESET}  "
        f"[{p_color}{proto_col}{RESET}]  "
        f"{GRAY}{size_col}{RESET}  "
        f"{src_col} {YELLOW}>>{RESET} {dst_col}"
        f"{details_part}"
    )


def print_capture_summary(stats: CaptureStats, resolver_stats: str) -> None:
    """Print end-of-capture traffic statistics, dropped count, top hosts, and cache metrics."""
    line = "=" * 74
    print(f"\n{CYAN}{line}{RESET}")
    print(f"{CYAN}{t('summary_title')}{RESET}")
    print(f"{CYAN}{line}{RESET}")
    print(f"  {BLUE}{t('summary_duration', seconds=stats.duration_seconds)}{RESET}")
    print(f"  {BLUE}{t('summary_packets', packets=stats.total_packets)}{RESET}")
    drop_color = RED if stats.dropped_packets > 0 else BLUE
    print(f"  {drop_color}{t('summary_dropped', dropped=stats.dropped_packets)}{RESET}")
    print(
        f"  {BLUE}"
        f"{t('summary_bytes', bytes_human=format_bytes(stats.total_bytes), bytes_raw=f'{stats.total_bytes:,}')}"
        f"{RESET}"
    )

    print(f"\n  {YELLOW}{t('summary_protocols')}{RESET}")
    if not stats.protocol_counts:
        print(f"  {GRAY}{t('summary_no_packets')}{RESET}")
    else:
        for proto, count in stats.protocol_counts.most_common():
            pct = (count / stats.total_packets * 100.0) if stats.total_packets else 0.0
            proto_col = fit_column(proto, 8)
            cnt_col = fit_column(str(count), 8, align="right")
            p_color = _proto_color(proto)
            print(f"    {p_color}{proto_col}{RESET} : {GREEN}{cnt_col}{RESET} ({pct:5.1f}%)")

    print(f"\n  {YELLOW}{t('summary_top_dests')}{RESET}")
    if not stats.destination_packets:
        print(f"  {GRAY}{t('summary_no_packets')}{RESET}")
    else:
        for rank, (dest, count) in enumerate(
            stats.destination_packets.most_common(10), start=1
        ):
            dest_bytes = stats.destination_bytes.get(dest, 0)
            rank_col = fit_column(f"{rank}.", 3, align="right")
            dest_col = fit_column(dest, 34)
            cnt_col = fit_column(f"{count} pkts", 12, align="right")
            bytes_col = fit_column(format_bytes(dest_bytes), 11, align="right")
            print(
                f"    {GRAY}{rank_col}{RESET} {CYAN}{dest_col}{RESET} "
                f"{GREEN}{cnt_col}{RESET}  {GRAY}({bytes_col}){RESET}"
            )

    print(f"\n  {BLUE}{t('summary_cache', stats=resolver_stats)}{RESET}")
    if stats.saved_files:
        joined = ", ".join(str(p) for p in stats.saved_files)
        print(f"  {GREEN}{t('summary_saved_files', files=joined)}{RESET}")
    print(f"{CYAN}{line}{RESET}")
