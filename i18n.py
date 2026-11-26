"""Internationalization (i18n) and OS-appropriate user configuration for VOID EYE."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

from arabic_tools import fix_ar

SUPPORTED_LANGUAGES: dict[str, str] = {
    "en": "English",
    "ar": "العربية (Arabic)",
    "tr": "Türkçe (Turkish)",
}

DEFAULT_LANGUAGE = "en"
APP_DIR_NAME = "void_eye"


def get_default_config_path() -> Path:
    """Return the per-user OS configuration file path.

    - Windows: %APPDATA%\\void_eye\\config.json
    - Linux/macOS: $XDG_CONFIG_HOME/void_eye/config.json or ~/.config/void_eye/config.json
    """
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        base_dir = (
            Path(appdata)
            if appdata
            else Path.home() / "AppData" / "Roaming"
        )
        return base_dir / APP_DIR_NAME / "config.json"

    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base_dir = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base_dir / APP_DIR_NAME / "config.json"


@dataclass
class AppConfig:
    """Persistent user preferences stored in the user's config directory."""

    language: str = DEFAULT_LANGUAGE
    bidi_enabled: bool = True
    legal_notice_shown: bool = False


TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        # Legal notice
        "legal_title": "LEGAL & ETHICAL NOTICE",
        "legal_body_1": (
            "VOID EYE is intended strictly for educational use and authorized "
            "network diagnostics."
        ),
        "legal_body_2": (
            "Capture traffic ONLY on networks you own or have explicit "
            "authorization to test."
        ),
        "legal_continue": "Press Enter to acknowledge and continue...",
        # Main menu
        "menu_opt_1_label": "Available network interfaces",
        "menu_opt_1_desc": "(select one and start capture)",
        "menu_opt_2_label": "Capture settings",
        "menu_opt_2_desc": "(BPF filter, protocol filter, save to pcap/CSV/JSONL)",
        "menu_opt_3_label": "Change language",
        "menu_opt_4_label": "Exit",
        "menu_prompt": "Select an option (1-4): ",
        "invalid_choice_range": "[-] Please enter a number between {min_val} and {max_val}.",
        "invalid_number": "[-] Invalid input. Please enter a valid number.",
        "goodbye": "[*] Exiting VOID EYE. Goodbye!",
        # Privileges & errors
        "priv_error_title": "[-] Insufficient privileges to capture network packets.",
        "priv_error_windows": (
            "    Run PowerShell or Command Prompt as Administrator and ensure "
            "Npcap is installed (https://npcap.com)."
        ),
        "priv_error_unix": "    Run with root privileges: sudo python3 void_eye.py",
        "sniff_error": "[-] Capture error: {error}",
        "invalid_bpf": "[-] Invalid BPF filter '{bpf}': {error}",
        "file_open_error": "[-] Cannot open output file '{path}': {error}",
        # Interfaces menu
        "ifaces_title": "  Available Network Interfaces:",
        "ifaces_none": "[-] No active network interfaces with a valid IP were found.",
        "ifaces_back": "[0] Back to main menu",
        "ifaces_prompt": "Select interface number (0-{count}): ",
        "iface_selected": "[+] Selected interface: {iface}",
        "iface_not_found": (
            "[-] Interface '{iface}' was not found. Use --list-interfaces or "
            "option [1] to inspect available interfaces."
        ),
        # Settings menu
        "settings_title": "  Capture Settings",
        "settings_bpf": "BPF Filter",
        "settings_proto": "Protocol Filter",
        "settings_pcap": "Save PCAP File",
        "settings_log": "Save CSV/JSONL Log",
        "settings_bidi": "Arabic BiDi Shaping",
        "settings_reset": "Reset settings to defaults",
        "settings_back": "Back to main menu",
        "settings_none": "None",
        "settings_all": "All",
        "settings_unlimited": "Unlimited",
        "settings_on": "Enabled",
        "settings_off": "Disabled",
        "settings_prompt": "Select setting to modify (0-6): ",
        "prompt_bpf": "Enter BPF filter (e.g. 'tcp port 443', empty to clear): ",
        "prompt_proto": "Enter protocol filter (all/tcp/udp/icmp/dns/arp/ipv6): ",
        "invalid_proto": (
            "[-] Invalid protocol '{proto}'. Choose from: "
            "all, tcp, udp, icmp, dns, arp, ipv6."
        ),
        "prompt_pcap": "Enter .pcap output path (empty to disable): ",
        "prompt_log": "Enter .csv or .jsonl log path (empty to disable): ",
        "log_ext_adjusted": "[*] Adjusted log extension -> {path}",
        "settings_updated": "[+] Capture settings updated.",
        "settings_was_reset": "[+] Settings restored to defaults.",
        # Language menu
        "lang_title": "  Select Language",
        "lang_back": "[0] Back to main menu",
        "lang_prompt": "Choose language (0-{count}): ",
        "lang_changed": "[+] Language changed to: {lang_name}",
        # Capture lifecycle & summary
        "capture_starting": (
            "[*] VOID EYE capturing on {iface}... (Press Ctrl+C to stop)"
        ),
        "capture_active_filters": "[*] Active filters -> BPF: {bpf} | Protocol: {proto}",
        "capture_limits": "[*] Limits -> Max packets: {max_pkts} | Duration: {duration}",
        "capture_saving_to": "[*] Recording output -> {targets}",
        "capture_live_stats": "[INFO] Packets: {count} | Traffic: {bytes_str} | {cache}",
        "capture_stopped": "[*] Capture stopped. Returning to main menu...",
        "summary_title": "  Capture Summary",
        "summary_duration": "Duration            : {seconds:.1f}s",
        "summary_packets": "Total Packets       : {packets}",
        "summary_dropped": "Dropped Packets     : {dropped}",
        "summary_bytes": "Total Bytes         : {bytes_human} ({bytes_raw} B)",
        "summary_protocols": "Protocol Breakdown  :",
        "summary_top_dests": "Top 10 Destinations :",
        "summary_no_packets": "  (no packets captured)",
        "summary_cache": "Resolver Cache      : {stats}",
        "summary_saved_files": "Saved Files         : {files}",
        # Special IP categories & cache stats
        "ip_localhost": "Localhost",
        "ip_lan": "LAN",
        "ip_cgnat": "CGNAT",
        "ip_link_local": "Link-Local",
        "ip_multicast": "Multicast",
        "ip_broadcast": "Broadcast",
        "ip_reserved": "Reserved",
        "cache_stats_fmt": (
            "Cache: {size}/{max_size} (hits={hits}, misses={misses}, "
            "neg={neg}, pending={pending})"
        ),
    },
    "ar": {
        # Legal notice
        "legal_title": "تنويه قانوني وأخلاقي",
        "legal_body_1": (
            "صُممت أداة VOID EYE للأغراض التعليمية وتشخيص الشبكات المصرح بها فقط."
        ),
        "legal_body_2": (
            "التقط الحزم فقط على الشبكات التي تملكها أو تملك تصريحاً رسمياً بفحصها."
        ),
        "legal_continue": "اضغط Enter للموافقة والمتابعة...",
        # Main menu
        "menu_opt_1_label": "واجهات الشبكة المتاحة",
        "menu_opt_1_desc": "(اختر واجهة وابدأ الالتقاط)",
        "menu_opt_2_label": "إعدادات الالتقاط",
        "menu_opt_2_desc": "(فلتر BPF، فلتر البروتوكول، الحفظ إلى pcap/CSV/JSONL)",
        "menu_opt_3_label": "تغيير اللغة",
        "menu_opt_4_label": "خروج",
        "menu_prompt": "اختر رقماً من القائمة (1-4): ",
        "invalid_choice_range": "[-] يرجى إدخال رقم بين {min_val} و {max_val}.",
        "invalid_number": "[-] إدخال غير صالح! يرجى إدخال رقم صحيح.",
        "goodbye": "[*] تم إغلاق VOID EYE. إلى اللقاء!",
        # Privileges & errors
        "priv_error_title": "[-] صلاحيات غير كافية لالتقاط حزم الشبكة.",
        "priv_error_windows": (
            "    شغّل الطرفية كمسؤول (Administrator) وتأكد من تثبيت برنامج Npcap."
        ),
        "priv_error_unix": "    شغّل الأداة بصلاحيات الجذر: sudo python3 void_eye.py",
        "sniff_error": "[-] حدث خطأ أثناء الالتقاط: {error}",
        "invalid_bpf": "[-] فلتر BPF غير صالح '{bpf}': {error}",
        "file_open_error": "[-] تعذر فتح ملف الإخراج '{path}': {error}",
        # Interfaces menu
        "ifaces_title": "  واجهات الشبكة المتاحة:",
        "ifaces_none": "[-] لم يتم العثور على أي واجهة شبكة نشطة بعنوان IP صالح.",
        "ifaces_back": "[0] العودة إلى القائمة الرئيسية",
        "ifaces_prompt": "اختر رقم الواجهة (0-{count}): ",
        "iface_selected": "[+] تم اختيار الواجهة: {iface}",
        "iface_not_found": "[-] لم يتم العثور على الواجهة '{iface}'. استخدم --list-interfaces أو الخيار [1].",
        # Settings menu
        "settings_title": "  إعدادات الالتقاط",
        "settings_bpf": "فلتر BPF",
        "settings_proto": "فلتر البروتوكول",
        "settings_pcap": "حفظ ملف PCAP",
        "settings_log": "حفظ سجل CSV/JSONL",
        "settings_bidi": "معالجة النص العربي (BiDi)",
        "settings_reset": "إعادة ضبط الإعدادات للوضع الافتراضي",
        "settings_back": "العودة إلى القائمة الرئيسية",
        "settings_none": "بدون",
        "settings_all": "الكل",
        "settings_unlimited": "غير محدود",
        "settings_on": "مفعّل",
        "settings_off": "معطّل",
        "settings_prompt": "اختر الإعداد للتعديل (0-6): ",
        "prompt_bpf": "أدخل فلتر BPF (مثال 'tcp port 443'، اتركه فارغاً للإلغاء): ",
        "prompt_proto": "أدخل البروتوكول (all/tcp/udp/icmp/dns/arp/ipv6): ",
        "invalid_proto": "[-] بروتوكول غير مدعوم '{proto}'. الخيارات: all, tcp, udp, icmp, dns, arp, ipv6.",
        "prompt_pcap": "أدخل مسار ملف .pcap (اتركه فارغاً للتعطيل): ",
        "prompt_log": "أدخل مسار ملف .csv أو .jsonl (اتركه فارغاً للتعطيل): ",
        "log_ext_adjusted": "[*] تم تعديل امتداد ملف السجل تلقائياً -> {path}",
        "settings_updated": "[+] تم تحديث الإعدادات بنجاح.",
        "settings_was_reset": "[+] تمت استعادة الإعدادات الافتراضية.",
        # Language menu
        "lang_title": "  اختيار اللغة",
        "lang_back": "[0] العودة إلى القائمة الرئيسية",
        "lang_prompt": "اختر اللغة (0-{count}): ",
        "lang_changed": "[+] تم تغيير اللغة إلى: {lang_name}",
        # Capture lifecycle & summary
        "capture_starting": "[*] بدأ VOID EYE الالتقاط على {iface}... (اضغط Ctrl+C للإيقاف)",
        "capture_active_filters": "[*] الفلاتر النشطة -> BPF: {bpf} | البروتوكول: {proto}",
        "capture_limits": "[*] الحدود -> أقصى حزم: {max_pkts} | المدة: {duration}",
        "capture_saving_to": "[*] الحفظ مفعل إلى -> {targets}",
        "capture_live_stats": "[معلومات] الحزم: {count} | الحجم: {bytes_str} | {cache}",
        "capture_stopped": "[*] تم إيقاف الالتقاط. جارٍ العودة للقائمة الرئيسية...",
        "summary_title": "  ملخص جلسة الالتقاط",
        "summary_duration": "المدة الزمنية        : {seconds:.1f} ثانية",
        "summary_packets": "إجمالي الحزم        : {packets}",
        "summary_dropped": "الحزم المفقودة       : {dropped}",
        "summary_bytes": "إجمالي البيانات     : {bytes_human} ({bytes_raw} بايت)",
        "summary_protocols": "توزيع البروتوكولات   :",
        "summary_top_dests": "أكثر 10 وجهات اتصالاً :",
        "summary_no_packets": "  (لم يتم التقاط أي حزم مطابقة)",
        "summary_cache": "ذاكرة الـ Resolver  : {stats}",
        "summary_saved_files": "الملفات المحفوظة    : {files}",
        # Special IP categories & cache stats
        "ip_localhost": "الجهاز المحلي",
        "ip_lan": "شبكة محلية",
        "ip_cgnat": "شبكة CGNAT",
        "ip_link_local": "ربط محلي",
        "ip_multicast": "بث متعدد",
        "ip_broadcast": "بث عام",
        "ip_reserved": "محجوز",
        "cache_stats_fmt": (
            "الذاكرة: {size}/{max_size} (إصابة={hits}، فقد={misses}، "
            "سلبي={neg}، انتظار={pending})"
        ),
    },
    "tr": {
        # Legal notice
        "legal_title": "YASAL VE ETİK UYARI",
        "legal_body_1": (
            "VOID EYE yalnızca eğitim amaçlı ve yetkili ağ tanılama işlemleri "
            "için geliştirilmiştir."
        ),
        "legal_body_2": (
            "Paket yakalamayı YALNIZCA sahibi olduğunuz veya açıkça test izniniz "
            "bulunan ağlarda gerçekleştirin."
        ),
        "legal_continue": "Kabul etmek ve devam etmek için Enter tuşuna basın...",
        # Main menu
        "menu_opt_1_label": "Kullanılabilir ağ arayüzleri",
        "menu_opt_1_desc": "(birini seçin ve yakalamayı başlatın)",
        "menu_opt_2_label": "Yakalama ayarları",
        "menu_opt_2_desc": "(BPF filtresi, protokol filtresi, pcap/CSV/JSONL kaydı)",
        "menu_opt_3_label": "Dili değiştir",
        "menu_opt_4_label": "Çıkış",
        "menu_prompt": "Bir seçenek girin (1-4): ",
        "invalid_choice_range": "[-] Lütfen {min_val} ile {max_val} arasında bir sayı girin.",
        "invalid_number": "[-] Geçersiz giriş. Lütfen geçerli bir sayı girin.",
        "goodbye": "[*] VOID EYE kapatılıyor. Güle güle!",
        # Privileges & errors
        "priv_error_title": "[-] Ağ paketlerini yakalamak için yetki yetersiz.",
        "priv_error_windows": (
            "    PowerShell veya Komut İstemi'ni Yönetici olarak çalıştırın ve "
            "Npcap'in kurulu olduğundan emin olun (https://npcap.com)."
        ),
        "priv_error_unix": "    Root yetkisiyle çalıştırın: sudo python3 void_eye.py",
        "sniff_error": "[-] Yakalama hatası: {error}",
        "invalid_bpf": "[-] Geçersiz BPF filtresi '{bpf}': {error}",
        "file_open_error": "[-] Çıktı dosyası açılamadı '{path}': {error}",
        # Interfaces menu
        "ifaces_title": "  Kullanılabilir Ağ Arayüzleri:",
        "ifaces_none": "[-] Geçerli IP adresine sahip aktif ağ arayüzü bulunamadı.",
        "ifaces_back": "[0] Ana menüye dön",
        "ifaces_prompt": "Arayüz numarasını seçin (0-{count}): ",
        "iface_selected": "[+] Seçilen arayüz: {iface}",
        "iface_not_found": (
            "[-] '{iface}' arayüzü bulunamadı. Mevcut arayüzleri görmek için "
            "--list-interfaces veya [1] seçeneğini kullanın."
        ),
        # Settings menu
        "settings_title": "  Yakalama Ayarları",
        "settings_bpf": "BPF Filtresi",
        "settings_proto": "Protokol Filtresi",
        "settings_pcap": "PCAP Dosyası Kaydet",
        "settings_log": "CSV/JSONL Günlüğü Kaydet",
        "settings_bidi": "Arapça BiDi Şekillendirme",
        "settings_reset": "Ayarları varsayılana sıfırla",
        "settings_back": "Ana menüye dön",
        "settings_none": "Yok",
        "settings_all": "Tümü",
        "settings_unlimited": "Sınırsız",
        "settings_on": "Etkin",
        "settings_off": "Devre Dışı",
        "settings_prompt": "Değiştirilecek ayarı seçin (0-6): ",
        "prompt_bpf": "BPF filtresi girin (örn. 'tcp port 443', temizlemek için boş bırakın): ",
        "prompt_proto": "Protokol filtresi girin (all/tcp/udp/icmp/dns/arp/ipv6): ",
        "invalid_proto": (
            "[-] Geçersiz protokol '{proto}'. İzin verilenler: "
            "all, tcp, udp, icmp, dns, arp, ipv6."
        ),
        "prompt_pcap": ".pcap dosya yolunu girin (kapatmak için boş bırakın): ",
        "prompt_log": ".csv veya .jsonl günlük yolunu girin (kapatmak için boş bırakın): ",
        "log_ext_adjusted": "[*] Günlük uzantısı ayarlandı -> {path}",
        "settings_updated": "[+] Yakalama ayarları güncellendi.",
        "settings_was_reset": "[+] Ayarlar varsayılana döndürüldü.",
        # Language menu
        "lang_title": "  Dil Seçimi",
        "lang_back": "[0] Ana menüye dön",
        "lang_prompt": "Dil seçin (0-{count}): ",
        "lang_changed": "[+] Dil değiştirildi: {lang_name}",
        # Capture lifecycle & summary
        "capture_starting": (
            "[*] VOID EYE {iface} üzerinde dinliyor... (Durdurmak için Ctrl+C)"
        ),
        "capture_active_filters": "[*] Aktif filtreler -> BPF: {bpf} | Protokol: {proto}",
        "capture_limits": "[*] Sınırlar -> Maks paket: {max_pkts} | Süre: {duration}",
        "capture_saving_to": "[*] Kayıt hedefleri -> {targets}",
        "capture_live_stats": "[BİLGİ] Paket: {count} | Veri: {bytes_str} | {cache}",
        "capture_stopped": "[*] Yakalama durduruldu. Ana menüye dönülüyor...",
        "summary_title": "  Yakalama Özeti",
        "summary_duration": "Süre                : {seconds:.1f} sn",
        "summary_packets": "Toplam Paket        : {packets}",
        "summary_dropped": "Düşürülen Paket     : {dropped}",
        "summary_bytes": "Toplam Boyut        : {bytes_human} ({bytes_raw} B)",
        "summary_protocols": "Protokol Dağılımı   :",
        "summary_top_dests": "İlk 10 Hedef        :",
        "summary_no_packets": "  (eşleşen paket yakalanmadı)",
        "summary_cache": "Çözümleyici Önbellek: {stats}",
        "summary_saved_files": "Kaydedilen Dosyalar : {files}",
        # Special IP categories & cache stats
        "ip_localhost": "Yerel Makine",
        "ip_lan": "Yerel Ağ",
        "ip_cgnat": "CGNAT",
        "ip_link_local": "Bağlantı-Yerel",
        "ip_multicast": "Çoklu Yayın",
        "ip_broadcast": "Genel Yayın",
        "ip_reserved": "Ayrılmış",
        "cache_stats_fmt": (
            "Önbellek: {size}/{max_size} (isabet={hits}, ıska={misses}, "
            "neg={neg}, bekleyen={pending})"
        ),
    },
}

_current_lang: str = DEFAULT_LANGUAGE
_bidi_enabled: bool = True


def get_language() -> str:
    """Return the active language code ('en', 'ar', or 'tr')."""
    return _current_lang


def set_language(lang: str) -> None:
    """Set the active UI language, falling back to 'en' if unsupported."""
    global _current_lang
    normalized = lang.strip().lower()
    _current_lang = normalized if normalized in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def is_bidi_enabled() -> bool:
    """Return True if Arabic reshaping + BiDi display reordering is active."""
    return _bidi_enabled


def set_bidi_enabled(enabled: bool) -> None:
    """Enable or disable Arabic reshaping + BiDi display reordering."""
    global _bidi_enabled
    _bidi_enabled = bool(enabled)


def format_display_text(text: str) -> str:
    """Apply Arabic reshaping/BiDi only when the active language is Arabic."""
    if _current_lang == "ar" and _bidi_enabled:
        return fix_ar(text, enabled=True)
    return text


def t(key: str, **kwargs: Any) -> str:
    """Translate *key* into the active language with English fallback."""
    lang_dict = TRANSLATIONS.get(_current_lang, TRANSLATIONS[DEFAULT_LANGUAGE])
    template = lang_dict.get(key)
    if template is None:
        template = TRANSLATIONS[DEFAULT_LANGUAGE].get(key, key)

    formatted = template.format(**kwargs) if kwargs else template
    return format_display_text(formatted)


def load_config(path: Path | None = None) -> AppConfig:
    """Load persistent configuration from user config dir, returning code defaults on failure."""
    target = path if path is not None else get_default_config_path()
    config = AppConfig()
    try:
        if not target.is_file():
            return config
        raw = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            lang = raw.get("language")
            if isinstance(lang, str) and lang.lower() in SUPPORTED_LANGUAGES:
                config.language = lang.lower()
            bidi = raw.get("bidi_enabled")
            if isinstance(bidi, bool):
                config.bidi_enabled = bidi
            notice = raw.get("legal_notice_shown")
            if isinstance(notice, bool):
                config.legal_notice_shown = notice
    except (OSError, json.JSONDecodeError, ValueError):
        pass

    return config


def save_config(config: AppConfig, path: Path | None = None) -> bool:
    """Persist configuration to user config dir; gracefully return False if unwritable."""
    target = path if path is not None else get_default_config_path()
    payload = {
        "language": config.language,
        "bidi_enabled": config.bidi_enabled,
        "legal_notice_shown": config.legal_notice_shown,
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        tmp_path.replace(target)
        return True
    except OSError:
        return False
