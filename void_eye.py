import scapy.all as scapy
from arabic_tools.arabic_tools import fix_ar
from resolver import resolve, cache_stats

# أكواد الألوان
GREEN  = '\033[92m'
BLUE   = '\033[94m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
RED    = '\033[91m'
RESET  = '\033[0m'

def get_service_name(port: int) -> str:
    services = {
        80:   "HTTP",
        443:  "HTTPS",
        53:   "DNS",
        21:   "FTP",
        22:   "SSH",
        25:   "SMTP",
        3306: "MySQL",
        8080: "HTTP-Alt",
        6379: "Redis",
        27017:"MongoDB"
    }
    return services.get(port, str(port))


# ============================
# عرض كروت الشبكة
# ============================

def list_interfaces() -> list[str]:
    """يجلب قائمة كروت الشبكة المتاحة"""
    try:
        # scapy يعطينا القاموس كامل
        ifaces = scapy.get_if_list()
        return ifaces
    except Exception:
        return []


def select_interface() -> str:
    """يعرض القائمة ويطلب من المستخدم الاختيار"""
    ifaces = list_interfaces()

    if not ifaces:
        print(RED + fix_ar("[-] لم يتم العثور على أي كرت شبكة!") + RESET)
        exit(1)

    print(CYAN + "=" * 50 + RESET)
    print(CYAN + fix_ar("  كروت الشبكة المتاحة:") + RESET)
    print(CYAN + "=" * 50 + RESET)

    for i, iface in enumerate(ifaces, start=1):
        # نحاول نجيب الـ IP الخاص بكل كرت
        try:
            ip = scapy.get_if_addr(iface)
        except Exception:
            ip = "N/A"

        # نلوّن الـ IP: أخضر إذا موجود، رمادي إذا ما فيه
        ip_colored = f"{GREEN}{ip}{RESET}" if ip != "0.0.0.0" else f"\033[90mN/A\033[0m"

        print(f"  {YELLOW}[{i}]{RESET} {BLUE}{iface:<20}{RESET} {ip_colored}")

    print(CYAN + "=" * 50 + RESET)

    while True:
        try:
            choice = input(BLUE + fix_ar(f"اختر رقم الكرت (1-{len(ifaces)}): ") + RESET).strip()
            index = int(choice) - 1
            if 0 <= index < len(ifaces):
                selected = ifaces[index]
                print(GREEN + fix_ar(f"[✓] تم اختيار: {selected}") + RESET)
                return selected
            else:
                print(RED + fix_ar(f"[-] أدخل رقم بين 1 و {len(ifaces)}") + RESET)
        except ValueError:
            print(RED + fix_ar("[-] أدخل رقماً صحيحاً فقط!") + RESET)


# ============================
# معالجة الـ Packets
# ============================

packet_count = 0

def process_packet(packet):
    global packet_count
    if packet.haslayer(scapy.IP):
        packet_count += 1

        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        src_name = resolve(src_ip)
        dst_name = resolve(dst_ip)

        proto_name = "Other"
        details    = ""

        if packet.haslayer(scapy.TCP):
            proto_name = f"{GREEN}TCP{RESET}"
            sport  = packet[scapy.TCP].sport
            dport  = packet[scapy.TCP].dport
            details = f"| {get_service_name(sport)} -> {get_service_name(dport)}"

        elif packet.haslayer(scapy.UDP):
            proto_name = f"{CYAN}UDP{RESET}"
            sport  = packet[scapy.UDP].sport
            dport  = packet[scapy.UDP].dport
            details = f"| {get_service_name(sport)} -> {get_service_name(dport)}"

        elif packet.haslayer(scapy.ICMP):
            proto_name = f"{YELLOW}ICMP{RESET}"
            details    = f"| Type: {packet[scapy.ICMP].type}"

        print(
            f"[{proto_name}] "
            f"{src_name:<28} {YELLOW}>>{RESET} "
            f"{dst_name:<28} {details}"
        )

        # كل 100 packet نطبع إحصائيات الـ Cache
        if packet_count % 100 == 0:
            print(f"{BLUE}[INFO] Packets: {packet_count} | {cache_stats()}{RESET}")


# ============================
# الشعار
# ============================

print(CYAN + """
██╗   ██╗ ██████╗ ██╗██████╗     ███████╗██╗   ██╗███████╗
██║   ██║██╔═══██╗██║██╔══██╗    ██╔════╝╚██╗ ██╔╝██╔════╝
██║   ██║██║   ██║██║██║  ██║    █████╗   ╚████╔╝ █████╗
╚██╗ ██╔╝██║   ██║██║██║  ██║    ██╔══╝    ╚██╔╝  ██╔══╝
 ╚████╔╝ ╚██████╔╝██║██████╔╝    ███████╗   ██║   ███████╗
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝     ╚══════╝   ╚═╝   ╚══════╝   
        MINI WIRESHARK - FROM ABOODY                                              
""" + RESET)

# ============================
# الاختيار والتشغيل
# ============================

interface = select_interface()
print(BLUE + fix_ar(f"[*] VOID EYE بدأ العمل على {interface}... (Ctrl+C للإيقاف)") + RESET)
print(CYAN + "-" * 60 + RESET)

try:
    scapy.sniff(iface=interface, store=False, prn=process_packet)
except KeyboardInterrupt:
    print(f"\n{RED}" + fix_ar(f"[*] تم الإيقاف | إجمالي الـ Packets: {packet_count} | {cache_stats()}") + RESET)
except Exception as e:
    print(RED + fix_ar(f"[-] حدث خطأ: {e}") + RESET)