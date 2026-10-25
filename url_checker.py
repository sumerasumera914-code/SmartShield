"""Rule-based URL analysis for SmartShield.

IMPORTANT: This file only LOOKS AT THE TEXT of a URL.
It never opens, visits or downloads the link.
It is NOT machine learning - it is a set of simple rules.
"""
import ipaddress
import json
import re
from urllib.parse import urlparse

import requests

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink",
}

KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "secure", "account",
    "password", "otp", "kyc", "bank", "wallet", "confirm", "suspended",
    "unlock", "prize", "winner", "claim", "free", "gift", "reward", "refund",
]

BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram",
    "netflix", "whatsapp", "paytm", "phonepe", "sbi", "hdfc", "icici", "flipkart",
]

RISKY_ENDINGS = (".zip", ".mov", ".xyz", ".top", ".tk", ".click", ".work", ".gq", ".ml", ".cf", ".ga")

STATUS_SUSPICIOUS = "Potentially Suspicious"
STATUS_OK = "No Obvious Warning Signs"
STATUS_UNABLE = "Unable to Analyse"


def _unable(message):
    return {"status": STATUS_UNABLE, "score": 0, "warnings": [], "notes": [message], "host": None}


def analyze_url(raw_url):
    """Analyse one URL string. Returns a dictionary with the result."""
    if raw_url is None or not str(raw_url).strip():
        return _unable("Please type or paste a URL first.")

    url = str(raw_url).strip()

    if re.search(r"\s", url):
        return _unable("A URL cannot contain spaces. Please check what you pasted.")
    if len(url) > 2048:
        return _unable("This URL is too long to analyse (more than 2048 characters).")

    notes = []
    if "://" not in url:
        notes.append("No http:// or https:// was typed, so http:// was assumed for analysis only.")
        parse_target = "http://" + url
        has_https = False
    else:
        parse_target = url
        has_https = url.lower().startswith("https://")

    try:
        parsed = urlparse(parse_target)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return _unable("This does not look like a valid URL.")

    if parsed.scheme.lower() not in ("http", "https"):
        return _unable("Only http:// and https:// links can be analysed.")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if not host or (not is_ip and "." not in host):
        return _unable("No valid website name (like example.com) was found in this URL.")
    if not is_ip and not re.fullmatch(r"[a-z0-9.\-]+", host):
        # Allow only normal letters, digits, dots and hyphens in the host name
        return _unable("The website name contains unusual characters, so it could not be analysed reliably.")

    warnings = []  # list of (weight, text)

    if len(url) > 100:
        warnings.append((1, f"The URL is very long ({len(url)} characters). Long URLs can hide the real destination."))
    elif len(url) > 75:
        warnings.append((1, f"The URL is fairly long ({len(url)} characters)."))

    if is_ip:
        warnings.append((2, "The link uses an IP address instead of a website name."))
    else:
        labels = host.split(".")
        subdomain_count = max(len(labels) - 2, 0)
        if subdomain_count >= 3:
            warnings.append((2, f"The website name has many subdomains ({subdomain_count}). Scammers sometimes stack names to look real."))

        if host.count("-") >= 3:
            warnings.append((1, "The website name contains many hyphens (-)."))

        if sum(ch.isdigit() for ch in host) >= 5:
            warnings.append((1, "The website name contains many digits."))

        if "xn--" in host:
            warnings.append((2, "The website name uses 'punycode' (xn--), which can be used to imitate real websites with look-alike letters."))

        registered = ".".join(labels[-2:])
        if registered in SHORTENERS or host in SHORTENERS:
            warnings.append((2, "This is a link-shortening service. The real destination is hidden."))

        if host.endswith(RISKY_ENDINGS):
            warnings.append((1, "The website ending (like .xyz or .top) is often seen in throw-away websites. Many normal sites use them too."))

        for brand in BRANDS:
            if brand in host and registered != f"{brand}.com" and not registered.startswith(f"{brand}."):
                warnings.append((2, f"The name '{brand}' appears in the website name, but the main domain is '{registered}'. This may be an imitation."))
                break

    if "@" in parse_target.split("://", 1)[1].split("/", 1)[0]:
        warnings.append((2, "The URL contains an '@' symbol before the website name. Everything before '@' is ignored by browsers."))

    if "//" in (parsed.path or ""):
        warnings.append((1, "The URL path contains a double slash (//), which can be used for redirect tricks."))

    if port not in (None, 80, 443):
        warnings.append((1, f"The URL uses an unusual port number ({port})."))

    found_words = [w for w in KEYWORDS if w in url.lower()]
    if len(found_words) >= 2:
        warnings.append((2, "The URL contains several pressure or account-related words: " + ", ".join(found_words[:5]) + "."))
    elif len(found_words) == 1:
        warnings.append((1, f"The URL contains the word '{found_words[0]}', which is common in scam links (and in normal links too)."))

    if not has_https:
        warnings.append((0, "The link does not use HTTPS. This is only a warning signal; many safe sites use HTTPS and some scam sites do too."))

    score = sum(weight for weight, _ in warnings)
    status = STATUS_SUSPICIOUS if score >= 2 else STATUS_OK

    return {
        "status": status,
        "score": score,
        "warnings": [text for _, text in warnings],
        "notes": notes,
        "host": host,
    }


def check_google_safe_browsing(url, api_key):
    """OPTIONAL: ask Google Safe Browsing about a URL.

    Only called when the user types an API key. Returns a dictionary:
      {"checked": True/False, "flagged": True/False/None, "message": "..."}
    "checked" is True ONLY if Google really answered.
    Note: this sends the URL text to Google. It does not open the URL itself.
    """
    if not api_key:
        return {"checked": False, "flagged": None, "message": "No API key provided, so no reputation check was done."}

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    body = {
        "client": {"clientId": "smartshield-student-project", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(endpoint, params={"key": api_key}, json=body, timeout=10)
    except requests.RequestException:
        return {"checked": False, "flagged": None, "message": "The reputation service could not be reached. No reputation check was done."}

    if response.status_code != 200:
        return {"checked": False, "flagged": None, "message": f"The reputation service returned an error (code {response.status_code}). No reputation check was done."}

    try:
        data = response.json()
    except json.JSONDecodeError:
        return {"checked": False, "flagged": None, "message": "The reputation service sent an unreadable answer. No reputation check was done."}

    if data.get("matches"):
        return {"checked": True, "flagged": True, "message": "Google Safe Browsing lists this URL as unsafe."}
    return {"checked": True, "flagged": False, "message": "Google Safe Browsing did not list this URL. This does not guarantee it is safe."}
