"""Scoring: ML probability + human-readable rules -> Safe / Suspicious / Dangerous + top reasons."""
import re
from functools import lru_cache

import joblib
import pandas as pd

from features import (BRANDS, FEATURE_NAMES, SHORTENERS, SUSPICIOUS_WORDS,
                      extract_features, find_brand, parse_url)

TRUSTED = set(BRANDS.values()) | {
    "google.com", "youtube.com", "wikipedia.org", "github.com", "microsoft.com", "apple.com",
    "kaggle.com", "python.org", "linkedin.com", "bbc.com",
}

# (weight, test(f, d), text(f, d)): the weight is how strongly the rule signals fraud
RULES = [
    (0.55, lambda f, d: f["brand_impersonation"],
     lambda f, d: f"Mentions the brand '{find_brand(d['host'], d['reg_domain'])[0]}' but the real owner is {BRANDS[find_brand(d['host'], d['reg_domain'])[0]]}, not {d['reg_domain']}"),
    (0.55, lambda f, d: f["brand_lookalike"],
     lambda f, d: f"Looks like a spoof of '{find_brand(d['host'], d['reg_domain'])[0]}' (letters swapped for digits)"),
    (0.50, lambda f, d: f["has_at"], lambda f, d: "Contains '@' - the text before it is a decoy, the real site is after it"),
    (0.50, lambda f, d: f["has_ip"], lambda f, d: "Uses a raw IP address instead of a domain name"),
    (0.45, lambda f, d: f["has_punycode"], lambda f, d: "Uses lookalike (punycode) characters in the domain"),
    (0.35, lambda f, d: f["is_shortener"], lambda f, d: "Shortened link - the real destination is hidden"),
    (0.30, lambda f, d: f["susp_tld"], lambda f, d: f"Uses a domain ending (.{d['tld']}) that is common in scam sites"),
    (0.25, lambda f, d: f["susp_word_in_host"] >= 1,
     lambda f, d: "Domain name contains pressure words like login/verify/secure"),
    (0.20, lambda f, d: f["susp_word_count"] >= 2,
     lambda f, d: "URL contains several sensitive words: " + ", ".join(w for w in SUSPICIOUS_WORDS if w in d["full"].lower())[:60]),
    (0.20, lambda f, d: f["num_subdomains"] >= 3, lambda f, d: f"Unusually many subdomains ({f['num_subdomains']})"),
    (0.15, lambda f, d: f["num_hyphens"] >= 2, lambda f, d: f"Many hyphens in the domain ({f['num_hyphens']})"),
    (0.15, lambda f, d: not f["is_https"], lambda f, d: "Not using HTTPS (unencrypted connection)"),
    (0.15, lambda f, d: f["odd_port"], lambda f, d: f"Unusual port number ({d['port']})"),
    (0.10, lambda f, d: f["digit_ratio"] > 0.25, lambda f, d: "Domain is full of random digits"),
    (0.10, lambda f, d: f["url_length"] > 90, lambda f, d: f"Very long URL ({f['url_length']} characters)"),
]


@lru_cache(maxsize=1)
def _bundle():
    return joblib.load("model/model.joblib")


def domain_age_days(domain: str):
    """Optional deep check (needs `pip install python-whois` + internet)."""
    try:
        import whois, datetime
        created = whois.whois(domain).creation_date
        if isinstance(created, list):
            created = created[0]
        return (datetime.datetime.now() - created).days if created else None
    except Exception:
        return None


def check_url(url: str, deep: bool = False) -> dict:
    d = parse_url(url)
    if not d["host"] or "." not in d["host"] and not d["host"].startswith("["):
        return {"url": url, "label": "Invalid", "score": 0, "color": "gray",
                "reasons": ["That does not look like a valid link"], "ml_probability": 0}
    f = extract_features(url)
    b = _bundle()
    ml = float(b["model"].predict_proba(pd.DataFrame([[f[n] for n in b["features"]]], columns=b["features"]))[0][1])

    triggered = sorted(((w, t(f, d)) for w, test, t in RULES if test(f, d)), key=lambda x: -x[0])
    rule_score = min(1.0, sum(w for w, _ in triggered))
    reasons = [text for _, text in triggered]
    score = 0.6 * ml + 0.4 * rule_score

    if deep:
        age = domain_age_days(d["reg_domain"])
        if age is not None and age < 30:
            score = min(1.0, score + 0.25)
            reasons.insert(0, f"Domain was registered only {age} days ago")
        elif age is not None:
            reasons.append(f"Domain age: {age} days")

    trusted = d["reg_domain"] in TRUSTED and not f["has_at"] and not f["has_punycode"]
    if trusted:
        score = min(score, 0.08)
        reasons = [f"Official domain of a known organisation ({d['reg_domain']})"]

    label, color = (("Safe", "green") if score < 0.35 else
                    ("Suspicious", "orange") if score < 0.65 else ("Dangerous", "red"))
    if not reasons:
        reasons = ["No suspicious patterns found in the link itself"]
    return {"url": url, "domain": d["reg_domain"], "label": label, "color": color,
            "score": round(score * 100), "ml_probability": round(ml, 3),
            "reasons": reasons[:3],
            "note": "Safe means no warning signs were found, not a guarantee." if label == "Safe" else None}
