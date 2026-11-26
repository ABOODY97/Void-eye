"""VOID EYE (Mini Wireshark) - CLI entry point and interactive session loop."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from typing import TYPE_CHECKING

from i18n import (
    SUPPORTED_LANGUAGES,
    load_config,
    set_bidi_enabled,
    set_language,
    t,
)
from resolver import get_resolver
import ui

if TYPE_CHECKING:
    from sniffer import CaptureSettings


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="void_eye",
        description="VOID EYE - Terminal packet sniffer with smart IP/domain resolution.",
    )
    parser.add_argument(
        "--iface",
        metavar="IFACE",
        help="Network interface name, index, IP, or GUID to start capturing immediately.",
    )
    parser.add_argument(
        "--lang",
        choices=tuple(SUPPORTED_LANGUAGES.keys()),
        help="UI language override (en, ar, tr).",
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        default="",
        metavar="BPF",
        help="BPF capture filter expression (e.g. 'tcp port 443').",
    )
    parser.add_argument(
        "--save",
        action="append",
        default=[],
        metavar="PATH",
        help="Output path (.pcap, .csv, or .json). May be specified multiple times.",
    )
    parser.add_argument(
        "--no-bidi",
        action="store_true",
        help="Disable Arabic reshaping/BiDi reordering for native-RTL terminals.",
    )
    return parser


def apply_save_paths(settings: CaptureSettings, raw_paths: list[str]) -> None:
    """Populate CaptureSettings output files from --save CLI arguments."""
    for raw in raw_paths:
        cleaned = raw.strip()
        if not cleaned:
            continue
        path = Path(cleaned)
        ext = path.suffix.lower()
        if ext in {".pcap", ".pcapng"}:
            settings.pcap_path = path
        elif ext in {".csv", ".json"}:
            settings.log_path = path
        else:
            # When given a bare stem (e.g. --save capture), enable both .pcap and .csv.
            settings.pcap_path = path.with_suffix(".pcap")
            settings.log_path = path.with_suffix(".csv")


def main(argv: list[str] | None = None) -> int:
    """Run VOID EYE via direct CLI capture or interactive main menu."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    ui.init_colors()

    config = load_config()
    active_lang = args.lang if args.lang else config.language
    set_language(active_lang)

    bidi_active = False if args.no_bidi else config.bidi_enabled
    set_bidi_enabled(bidi_active)

    is_tty = sys.stdin.isatty()
    if not ui.show_legal_notice_once(config, interactive=is_tty and not args.iface):
        print(f"{ui.YELLOW}{t('goodbye')}{ui.RESET}")
        return 0

    from sniffer import CaptureSettings, find_interface, list_interfaces, run_capture

    settings = CaptureSettings(bpf_filter=args.bpf_filter.strip())
    apply_save_paths(settings, args.save)

    resolver = get_resolver()

    try:
        # Direct non-menu CLI mode when --iface is supplied
        if args.iface:
            interfaces = list_interfaces()
            target = find_interface(args.iface, interfaces)
            if target is None:
                print(f"{ui.RED}{t('iface_not_found', iface=args.iface)}{ui.RESET}")
                return 1
            result = run_capture(target, settings, resolver=resolver)
            return 0 if result is not None else 1

        # Interactive main menu loop
        while True:
            choice = ui.prompt_main_menu()
            if choice is None or choice == 4:
                print(f"{ui.CYAN}{t('goodbye')}{ui.RESET}")
                return 0

            if choice == 1:
                interfaces = list_interfaces()
                selected = ui.prompt_interface_menu(interfaces)
                if selected is not None:
                    run_capture(selected, settings, resolver=resolver)
                    print(f"{ui.YELLOW}{t('capture_stopped')}{ui.RESET}")
            elif choice == 2:
                ui.run_settings_menu(settings, config)
            elif choice == 3:
                ui.run_language_menu(config)
    except KeyboardInterrupt:
        print(f"\n{ui.CYAN}{t('goodbye')}{ui.RESET}")
        return 0
    finally:
        resolver.shutdown()


if __name__ == "__main__":
    sys.exit(main())
