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
أداة **VOID EYE** هي أداة خفيفة وتفاعلية لمراقبة وتحليل حزم الشبكة (Packet Sniffer) عبر الطرفية (Terminal) مبنية بلغة **Python 3.10+** ومكتبة **Scapy**. تقوم الأداة بالتقاط الحزم الحية (`IPv4`، `IPv6`، `ARP`، `TCP`، `UDP`، `ICMP`، `DNS`، `TLS`) وعرض المصدر والوجهة بوضوح مع التعرف الذكي وغير المتزامن على أسماء النطاقات والخدمات.

## أبرز المميزات
* **متعددة اللغات (i18n):** تدعم الإنجليزية (الافتراضية)، العربية (مع معالجة الحروف والاتجاه عبر `arabic-reshaper` و`python-bidi` وخيار `--no-bidi` للطرفيات الحديثة)، والتركية، مع حفظ اللغة تلقائياً في `config.json`.
* **استخراج أسماء النطاقات الحقيقية:** قراءة استعلامات `DNS (qname)` وامتداد `TLS SNI (server_name)` وتفضيلها على تخمين عناوين الـ IP، مع التعلّم السلبي من ردود DNS.
* **نظام Resolver غير متزامن ودقيق:**
  * مطابقة نطاقات الشبكة بصيغة `CIDR` عبر مكتبة `ipaddress` لكل من `IPv4` و`IPv6`.
  * استعلامات `Reverse DNS` في الخلفية بدون تجميد التقاط الحزم، مع ذاكرة مؤقتة محدودة الحجم والزمن (`LRU + TTL` و`Negative Caching`).
  * استثناء العناوين الخاصة والمحلية (`LAN` / `Localhost` / `Link-Local`) من استعلامات DNS العكسية.
  * دعم اللواحق العامة متعددة الأجزاء مثل `co.uk` و`com.tr` و`com.sa` ومنع التطابق الخاطئ للكلمات الجزئية.
* **فلاتر وتصدير احترافي:** دعم فلاتر `BPF` وفلاتر البروتوكولات وحفظ الجلسات بصيغ `.pcap` و`.csv` و`.json`، مع ملخص إحصائي شامل عند انتهاء الالتقاط.

## المتطلبات والتثبيت
1. **Python 3.10** أو أحدث.
2. **لمستخدمي Windows:** يجب تثبيت برنامج **[Npcap](https://npcap.com/)** (مع تفعيل خيار *Install Npcap in WinPcap API-compatible Mode*)، وتشغيل الطرفية (`PowerShell` أو `CMD`) بصلاحيات **المسؤول (Run as Administrator)**.
3. **لمستخدمي Linux / macOS:** يتطلب التشغيل صلاحيات الجذر (`sudo`) ومكتبة `libpcap`.

تثبيت الحزم:
```bash
pip install -r requirements.txt
```

## طريقة التشغيل
التشغيل التفاعلي (القائمة الرئيسية):
```bash
# Linux / macOS
sudo python3 void_eye.py

# Windows (داخل PowerShell كمسؤول Administrator)
python void_eye.py
```

التشغيل عبر سطر الأوامر (CLI):
```bash
python void_eye.py --lang ar
python void_eye.py --iface "Wi-Fi" --filter "tcp port 443" --save capture.pcap --save traffic.csv
python void_eye.py --lang ar --no-bidi
```

## إخلاء المسؤولية القانونية والأخلاقية
> **تنويه هام:** صُممت هذه الأداة للأغراض التعليمية وتشخيص الشبكات المصرح بها فقط. يُحظر استخدامها لاعتراض حركة البيانات على شبكات لا تملكها أو لا تملك تصريحاً صريحاً ومكتوباً بفحصها.

</div>

---

## English Overview

**VOID EYE (Mini Wireshark)** is a cross-platform terminal packet sniffer written in **Python 3.10+** on top of **Scapy**. It captures `IPv4`, `IPv6`, and `ARP` traffic in real time, extracts `DNS` query names and `TLS ClientHello SNI` hostnames, resolves public IPs asynchronously without stalling capture callbacks, and exports sessions to `.pcap`, `.csv`, and `.json`.

### Prerequisites & Usage
- **Python 3.10+**
- **Windows:** Install **[Npcap](https://npcap.com/)** (enable *WinPcap API-compatible mode*) and run PowerShell / Command Prompt **as Administrator**.
- **Linux / macOS:** Run with `sudo` (`libpcap` required).

```bash
pip install -r requirements.txt

# Interactive menu (English by default; switch to Arabic/Turkish in menu [3] or via --lang)
sudo python3 void_eye.py          # Linux / macOS
python void_eye.py                # Windows (Administrator shell)

# Direct CLI capture
python void_eye.py --iface eth0 --lang en --filter "port 53 or port 443" --save session.pcap --save session.json

# Run unit tests
pytest
```

> **Legal & Ethical Notice:** For educational purposes and authorized network diagnostics only. Capture packets strictly on networks you own or are explicitly authorized to test.

---

## Türkçe Genel Bakış

**VOID EYE (Mini Wireshark)**, **Python 3.10+** ve **Scapy** ile geliştirilmiş uçbirim (terminal) tabanlı bir ağ paket yakalama ve analiz aracıdır. `IPv4`, `IPv6` ve `ARP` trafiğini gerçek zamanlı izler; `DNS (qname)` ve `TLS SNI` alan adlarını yakalar, arka planda engellemesiz (asenkron) ters DNS çözümlemesi yapar ve oturumları `.pcap`, `.csv` veya `.json` olarak kaydeder.

### Gereksinimler ve Kullanım
- **Python 3.10+**
- **Windows:** **[Npcap](https://npcap.com/)** sürücüsünü kurun ve terminali **Yönetici (Administrator)** olarak başlatın.
- **Linux / macOS:** `sudo` yetkisiyle çalıştırın.

```bash
pip install -r requirements.txt
python void_eye.py --lang tr
```

> **Yasal Uyarı:** Yalnızca eğitim ve yetkili ağ analizi amaçlıdır. Sadece sahibi olduğunuz veya açıkça test izniniz bulunan ağlarda kullanın.
