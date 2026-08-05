import socket
import json
import os

# ============================
# تحميل القاموس من الملف
# ============================
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DB_PATH  = os.path.join(_BASE_DIR, "known_ips.json")

with open(_DB_PATH, "r", encoding="utf-8") as f:
    _DB = json.load(f)

KNOWN_IPS      = _DB["known_ips"]       # IP كاملة
KNOWN_RANGES   = _DB["known_ranges"]    # أول جزئين من الـ IP
DOMAIN_KEYWORDS = _DB["domain_keywords"] # كلمات في الـ hostname

# ============================
# Cache في الذاكرة
# ============================
_cache: dict[str, str] = {}

# ============================
# دوال المساعدة
# ============================

def _clean_hostname(hostname: str) -> str:
    """يحول hostname طويل لاسم موقع نظيف"""
    h = hostname.lower()
    for keyword, name in DOMAIN_KEYWORDS.items():
        if keyword in h:
            return name
    # إرجاع آخر جزئين: sub.example.com -> example.com
    parts = h.split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return hostname


def _check_range(ip: str) -> str | None:
    """يفحص إذا الـ IP ينتمي لنطاق معروف"""
    parts = ip.split(".")
    if len(parts) >= 2:
        prefix = f"{parts[0]}.{parts[1]}"
        return KNOWN_RANGES.get(prefix)
    return None


# ============================
# الدالة الرئيسية
# ============================

def resolve(ip: str) -> str:
    """
    يحول IP إلى اسم موقع بالترتيب:
    1. Cache
    2. Known IPs (exact)
    3. Known Ranges (أول جزئين)
    4. Reverse DNS
    5. الـ IP نفسه
    """

    # 1. Cache
    if ip in _cache:
        return _cache[ip]

    # 2. Known IPs
    if ip in KNOWN_IPS:
        result = KNOWN_IPS[ip]
        _cache[ip] = result
        return result

    # 3. Known Ranges
    range_match = _check_range(ip)
    if range_match:
        _cache[ip] = range_match
        return range_match

    # 4. Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result = _clean_hostname(hostname)
        _cache[ip] = result
        return result
    except (socket.herror, socket.gaierror):
        pass

    # 5. الـ IP نفسه كـ fallback
    _cache[ip] = ip
    return ip


def cache_stats() -> str:
    """إحصائيات الـ Cache"""
    return f"Cache: {len(_cache)} entries"