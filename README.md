<div dir="ltr">

```text
██╗   ██╗ ██████╗ ██╗██████╗     ███████╗██╗   ██╗███████╗
██║   ██║██╔═══██╗██║██╔══██╗    ██╔════╝╚██╗ ██╔╝██╔════╝
██║   ██║██║   ██║██║██║  ██║    █████╗   ╚████╔╝ █████╗
╚██╗ ██╔╝██║   ██║██║██║  ██║    ██╔══╝    ╚██╔╝  ██╔══╝
 ╚████╔╝ ╚██████╔╝██║██████╔╝    ███████╗   ██║   ███████╗
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝     ╚══════╝   ╚═╝   ╚══════╝
        MINI WIRESHARK - FROM ABOODY
```

</div>

<div dir="rtl">

# أداة VOID EYE (Mini Wireshark)

## نبذة عن الأداة
أداة **VOID EYE** هي أداة خفيفة وآمنة لمراقبة وتحليل حزم الشبكة (Packet Sniffer) عبر الطرفية مبنية بلغة **Python 3.10+** ومكتبة **Scapy**. تلتقط الأداة الحزم الحية (`IPv4`، `IPv6`، `ARP`، `TCP`، `UDP`، `ICMP`، `DNS`، `TLS`، `QUIC`) عبر طابور غير حاجب (Non-blocking Queue) مع استخراج آمن لأسماء النطاقات وحماية ضد حقن الطرفية وتزوير DNS.

## أبرز المميزات
* **الأمان والموثوقية:**
  * تعقيم كامل للنصوص القادمة من الشبكة (`sanitize_network_text`) لمنع حقن أكواد ANSI/التحكم في الطرفية، وحماية ملفات `CSV` من حقن المعادلات (`= + - @`).
  * مقاومة تزوير الـ DNS: لا يتم تعلّم عناوين `A/AAAA` إلا عند مطابقة استعلام صادر سابق (نفس العميل، الخادم، معرّف العملية `TXID`، واسم النطاق)، مع تمييز الأسماء المتعلَّمة من الشبكة بالبادئة `~` وترتيب الأولوية `SNI > DNS > rDNS > CIDR`.
  * منع تذبذب أسماء النطاقات على عناوين الـ CDN المشتركة مع الاحتفاظ بآخر اسم مستخرج من `SNI`.
* **بروتوكولات حديثة وأداء عالٍ:**
  * إعادة تجميع رسائل `TLS ClientHello` المقسمة على عدة مقاطع `TCP`، وفك تشفير حزم `QUIC Initial` (`UDP 443`) لاستخراج `SNI`.
  * طابور التقاط غير حاجب مع إحصاء الحزم المفقودة (`Dropped Packets`)، وطوابع زمنية دقيقة من `packet.time`، وتفريغ دوري لملفات `.pcap` وسجلات `.jsonl` و`.csv`.
  * تمييز عناوين `100.64.0.0/10` كـ `CGNAT` بشكل مستقل عن `LAN`، وأداة اختيارية `tools/update_ranges.py` لتحديث نطاقات `CIDR` من المصادر الرسمية.
* **متعددة اللغات وتخزين نظيف للإعدادات:**
  * دعم الإنجليزية (الافتراضية)، العربية (`--no-bidi` للطرفيات الحديثة)، والتركية، مع حفظ الإعدادات في مجلد المستخدم (`%APPDATA%\void_eye` على Windows أو `~/.config/void_eye` على Linux/macOS).

## المتطلبات والتثبيت
1. **Python 3.10** أو أحدث.
2. **Windows:** تثبيت **[Npcap](https://npcap.com/)** (تفعيل *WinPcap API-compatible Mode*) وتشغيل الطرفية بصلاحيات **المسؤول (Administrator)**.
3. **Linux / macOS:** التشغيل بصلاحيات `sudo` مع وجود `libpcap`.

```bash
pip install -e ".[dev]"
# أو لتثبيت الاعتماديات فقط:
pip install -r requirements.txt
```

## طريقة التشغيل
```bash
# عرض الواجهات المتاحة بدون الحاجة لبدء الالتقاط
void-eye --list-interfaces

# التشغيل التفاعلي
sudo void-eye                     # Linux / macOS
void-eye                          # Windows (Administrator)

# التقاط محدد بعدد حزم أو مدة زمنية وحفظ بصيغة PCAP و JSONL
void-eye --iface "Wi-Fi" --filter "port 443 or port 53" --max-packets 200 --duration 30 --save capture.pcap --save traffic.jsonl

# تحديث نطاقات CIDR اختيارياً (آمن عند انقطاع الإنترنت)
python tools/update_ranges.py
```

## إخلاء المسؤولية القانونية والأخلاقية
> **تنويه هام:** صُممت هذه الأداة للأغراض التعليمية وتشخيص الشبكات المصرح بها فقط. يُحظر استخدامها لاعتراض حركة البيانات على شبكات لا تملكها أو لا تملك تصريحاً صريحاً بفحصها.

</div>

---

## English Overview

**VOID EYE (Mini Wireshark)** is a hardened cross-platform terminal packet sniffer built with **Python 3.10+** and **Scapy**.

### Key Highlights
- **Security Hardening:** Neutralizes terminal escape/control sequences (`sanitize_network_text`), prevents CSV formula injection, validates DNS answers against pending outbound queries `(client, server, txid, qname)` to block unsolicited cache poisoning, enforces `SNI > DNS > rDNS > CIDR` precedence without CDN flapping, and prefixes unauthenticated learned names with `~`.
- **Deep Dissection & Non-Blocking Pipeline:** Producer-consumer capture queue with drop tracking, `packet.time` timestamps, multi-segment TCP `TLS ClientHello` SNI reassembly, RFC 9001 `QUIC Initial` (`UDP 443`) SNI extraction, `CGNAT` (`100.64.0.0/10`) classification, and buffered `.pcap` + `.jsonl` / `.csv` exports.
- **User Config & Tooling:** Stores config in `%APPDATA%\void_eye` (Windows) or `~/.config/void_eye` (Linux/macOS); ships with `void-eye` CLI entry point, `tools/update_ranges.py`, `ruff`/`mypy` config, and cross-OS GitHub Actions CI.

```bash
pip install -e ".[dev]"
void-eye --list-interfaces
sudo void-eye --iface eth0 --max-packets 100 --duration 20 --save out.pcap --save out.jsonl
pytest -v
```

---

## Türkçe Genel Bakış

**VOID EYE (Mini Wireshark)**, **Python 3.10+** ve **Scapy** tabanlı, güvenlik odaklı bir uçbirim paket yakalama aracıdır. Uçbirim kaçış dizisi (ANSI/kontrol karakteri) enjeksiyonunu ve CSV formül enjeksiyonunu engeller; sahte DNS yanıtlarına karşı sorgu eşleştirmesi yapar (`SNI > DNS > rDNS > CIDR`), çok parçalı TCP `TLS ClientHello` ve `QUIC Initial (UDP 443)` SNI alan adlarını çözümler ve oturumları `.pcap`, `.jsonl` veya `.csv` olarak kaydeder.

```bash
pip install -e ".[dev]"
void-eye --list-interfaces
void-eye --lang tr --max-packets 100 --duration 30
```
