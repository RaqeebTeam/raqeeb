"""URL -> numeric features. Pure Python, never visits the URL (safe + instant)."""
import math
import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "bank", "confirm",
    "password", "wallet", "payment", "billing", "suspend", "unlock", "alert",
    "invoice", "refund", "free", "bonus", "gift", "prize", "claim", "otp",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "country",
    "zip", "mov", "icu", "buzz", "rest", "fit", "cam", "monster", "support", "cyou",
}

# brand keyword -> its real registered domain (includes a few regional ones)
BRANDS = {
    "paypal": "paypal.com", "apple": "apple.com", "google": "google.com",
    "microsoft": "microsoft.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "binance": "binance.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "aramex": "aramex.com", "emiratesnbd": "emiratesnbd.com", "mashreq": "mashreqbank.com",
    "adcb": "adcb.com", "alrajhi": "alrajhibank.com.sa", "etisalat": "etisalat.ae",
    "emirates": "emirates.com", "visa": "visa.com", "mastercard": "mastercard.com",
    "chase": "chase.com", "dewa": "dewa.gov.ae",
}

TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "com.au", "com.sa", "co.ae", "gov.ae", "net.ae", "org.ae",
    "ac.ae", "com.eg", "co.in", "com.br",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host)) and "." in host


def split_host(host: str):
    """Return (subdomain, registered_domain, tld) without needing the public suffix list."""
    if not host or _is_ip(host):
        return "", host, ""
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[:-3]), ".".join(parts[-3:]), ".".join(parts[-2:])
    if len(parts) >= 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:]), parts[-1]
    return "", host, ""


def parse_url(url: str) -> dict:
    url = (url or "").strip()
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    full = url if has_scheme else "https://" + url   # pasted bare domains: assume https
    p = urlparse(full)
    host = (p.hostname or "").lower()
    sub, reg, tld = split_host(host)
    return {
        "url": url, "full": full, "scheme": p.scheme.lower(), "host": host,
        "netloc": p.netloc, "sub": sub, "reg_domain": reg, "tld": tld,
        "path": p.path or "", "query": p.query or "", "port": p.port if _safe_port(p) else None,
    }


def _safe_port(p):
    try:
        p.port
        return True
    except ValueError:
        return False


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def find_brand(host: str, reg_domain: str):
    """Return (brand, kind) if the host mentions a brand it does not own.
    kind = 'impersonation' (brand name inside a foreign domain) or 'lookalike' (paypa1)."""
    tokens = [t for t in re.split(r"[.\-_0-9]", host) if t]
    leet_host = host.translate(LEET)
    leet_tokens = [t for t in re.split(r"[.\-_0-9]", leet_host) if t]
    for brand, real in BRANDS.items():
        if reg_domain == real:
            continue
        in_raw = brand in tokens or (len(brand) >= 6 and brand in host)
        if in_raw:
            return brand, "impersonation"
        in_leet = brand in leet_tokens or (len(brand) >= 6 and brand in leet_host)
        if in_leet:
            return brand, "lookalike"
    return None, None


FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots",
    "num_hyphens", "num_digits", "digit_ratio", "num_subdomains", "has_at",
    "has_ip", "is_https", "susp_word_count", "susp_word_in_host", "is_shortener",
    "has_punycode", "brand_impersonation", "brand_lookalike", "susp_tld",
    "odd_port", "host_entropy", "num_special_chars", "path_depth", "double_slash_in_path",
]


def extract_features(url: str) -> dict:
    d = parse_url(url)
    host, full, low = d["host"], d["full"], d["full"].lower()
    sub_labels = [l for l in d["sub"].split(".") if l and l != "www"]
    brand, kind = find_brand(host, d["reg_domain"])
    return {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(d["path"]),
        "query_length": len(d["query"]),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_digits": sum(c.isdigit() for c in full),
        "digit_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "num_subdomains": len(sub_labels),
        "has_at": int("@" in d["netloc"]),
        "has_ip": int(_is_ip(host)),
        "is_https": int(d["scheme"] == "https"),
        "susp_word_count": sum(low.count(w) for w in SUSPICIOUS_WORDS),
        "susp_word_in_host": sum(host.count(w) for w in SUSPICIOUS_WORDS),
        "is_shortener": int(d["reg_domain"] in SHORTENERS),
        "has_punycode": int("xn--" in host),
        "brand_impersonation": int(kind == "impersonation"),
        "brand_lookalike": int(kind == "lookalike"),
        "susp_tld": int(d["tld"] in SUSPICIOUS_TLDS),
        "odd_port": int(d["port"] not in (None, 80, 443)),
        "host_entropy": round(_entropy(host), 3),
        "num_special_chars": sum(full.count(c) for c in "?&=%_~"),
        "path_depth": len([s for s in d["path"].split("/") if s]),
        "double_slash_in_path": int("//" in d["path"]),
    }


def feature_vector(url: str):
    f = extract_features(url)
    return [f[n] for n in FEATURE_NAMES]
