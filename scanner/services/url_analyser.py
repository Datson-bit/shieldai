import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account",
    "banking", "signin", "password", "credential", "wallet",
    "opay", "gtbank", "zenith", "access", "uba", "firstbank",
    "paystack", "flutterwave", "kuda", "moniepoint", "palmpay",
    "jamb", "waec", "firs", "immigration", "nin", "bvn",
    "alert", "suspended", "unusual", "blocked", "unlock",
]

LOOKALIKE_PATTERNS = [
    r"g[o0][o0]gle", r"faceb[o0][o0]k", r"paypa[l1]",
    r"gtb[a4]nk", r"[o0]pay", r"kud[a4]", r"[z2]enith",
    r"[a4]ccess", r"firstb[a4]nk", r"[j1]amb",
]


def analyse_url(url: str) -> dict:
    score = 0
    flags = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full_url = url.lower()
        path = parsed.path.lower()

        # Check 1 — IP address used instead of domain
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        if ip_pattern.match(domain):
            score += 30
            flags.append("IP address used instead of a domain name — highly suspicious")

        # Check 2 — URL length
        if len(url) > 100:
            score += 10
            flags.append(f"Unusually long URL ({len(url)} characters)")

        # Check 3 — Excessive subdomains
        subdomain_count = domain.count(".") 
        if subdomain_count > 3:
            score += 15
            flags.append(f"Excessive subdomains detected ({subdomain_count} dots in domain)")

        # Check 4 — Suspicious keywords in URL
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
        if len(found_keywords) >= 2:
            score += 20
            flags.append(f"Multiple suspicious keywords found: {', '.join(found_keywords[:3])}")
        elif len(found_keywords) == 1:
            score += 10
            flags.append(f"Suspicious keyword found: {found_keywords[0]}")

        # Check 5 — Lookalike domain patterns
        for pattern in LOOKALIKE_PATTERNS:
            if re.search(pattern, domain):
                score += 25
                flags.append(f"Domain appears to impersonate a known brand")
                break

        # Check 6 — HTTP not HTTPS
        if parsed.scheme == "http":
            score += 15
            flags.append("No SSL encryption — site uses HTTP not HTTPS")

        # Check 7 — Suspicious TLDs
        suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score += 20
                flags.append(f"Suspicious domain extension: {tld}")
                break

        # Check 8 — @ symbol in URL (tricks browsers)
        if "@" in url:
            score += 25
            flags.append("@ symbol detected in URL — common phishing trick")

        # Check 9 — Double slashes in path
        if "//" in path:
            score += 10
            flags.append("Double slashes detected in URL path")

        # Check 10 — Hyphen abuse in domain
        if domain.count("-") > 3:
            score += 15
            flags.append(f"Excessive hyphens in domain name — common in fake sites")

    except Exception as e:
        flags.append("Could not fully parse URL structure")

    # Cap at 100
    score = min(score, 100)

    if score >= 60:
        status = "FAILED"
        note = f"{len(flags)} suspicious pattern(s) detected in URL structure"
    elif score >= 25:
        status = "WARNING"
        note = f"{len(flags)} minor suspicious pattern(s) detected"
    else:
        status = "PASSED"
        note = "URL structure appears normal"

    return {
        "status": status,
        "score": score,
        "note": note,
        "flags": flags,
    }
