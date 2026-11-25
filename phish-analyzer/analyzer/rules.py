from __future__ import annotations

from difflib import SequenceMatcher
import ipaddress
import re
from urllib.parse import urlsplit

from .models import EmailData, Finding

BRANDS = {
    "paypal": {"paypal.com"}, "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "google": {"google.com", "gmail.com"}, "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in"},
    "bank": {"chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com"},
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "shorturl.at"}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".lnk", ".html", ".htm", ".iso", ".zip", ".docm", ".xlsm"}
URGENCY_TERMS = ("verify your account", "within 24 hours", "password expires", "account will be closed",
                 "immediate action", "suspended", "urgent", "final warning", "confirm your password")


def _domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().strip("> ").lower().rstrip(".")


def _host(url: str) -> str:
    try:
        parsed = urlsplit(url.strip() if "://" in url else "//" + url.strip())
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _registrable(domain: str) -> str:
    bits = domain.lower().strip(".").split(".")
    if len(bits) >= 3 and ".".join(bits[-2:]) in {"co.uk", "com.au", "co.in", "com.br", "co.jp"}:
        return ".".join(bits[-3:])
    return ".".join(bits[-2:]) if len(bits) >= 2 else domain.lower()


def _distance(a: str, b: str) -> int:
    # Similarity fallback catches character substitutions such as rnicrosoft.
    if a == b:
        return 0
    if len(a) > 32 or len(b) > 32:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_lookalike(domain: str) -> str | None:
    reg = _registrable(domain)
    label = reg.split(".")[0]
    # Brand roots with frequent impersonation. The explicit roots prevent
    # unrelated domains from matching simply because they contain a brand word.
    known = {d.split(".")[0] for roots in BRANDS.values() for d in roots}
    for brand in known:
        if label == brand:
            continue
        substituted = label.replace("rn", "m").translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))
        if _distance(substituted, brand) <= 1 or SequenceMatcher(None, substituted, brand).ratio() >= 0.82:
            return brand
    return None


def check_rules(email: EmailData) -> list[Finding]:
    findings: list[Finding] = []
    sender_domain = _domain(email.from_address)
    display_domain_match = re.search(r"(?:https?://)?(?:www\.)?([A-Z0-9.-]+\.[A-Z]{2,})\b", email.from_name, re.I)
    if display_domain_match:
        shown_domain = display_domain_match.group(1).lower().rstrip(".")
        if sender_domain and _registrable(shown_domain) != _registrable(sender_domain):
            findings.append(Finding(id="display-name-domain", title="Display name shows a different domain", severity="high",
                                    evidence=f"From display name: {email.from_name}; sender address: {email.from_address}"))

    reply_domain = _domain(email.reply_to)
    if sender_domain and reply_domain and _registrable(sender_domain) != _registrable(reply_domain):
        findings.append(Finding(id="reply-to-mismatch", title="From and Reply-To domains differ", severity="high",
                                evidence=f"From: {email.from_address}; Reply-To: {email.reply_to}"))

    for method in ("spf", "dkim", "dmarc"):
        result = email.auth_results.get(method)
        if result in {"fail", "softfail", "permerror", "temperror", "neutral"}:
            findings.append(Finding(id=f"auth-{method}", title=f"{method.upper()} authentication did not pass", severity="high" if result == "fail" else "medium",
                                    evidence=f"Authentication-Results: {method}={result}"))
        elif not result or result == "none":
            findings.append(Finding(id=f"auth-{method}", title=f"{method.upper()} result is missing", severity="medium",
                                    evidence=f"Authentication-Results does not report {method.upper()}"))

    seen: set[str] = set()
    for link in email.links:
        host = _host(link.href)
        if link.display_url_mismatch:
            findings.append(Finding(id="link-text-mismatch", title="Link text and destination differ", severity="high",
                                    evidence=f"Visible: {link.visible_text}; destination: {link.href}"))
        if not host:
            continue
        if host not in seen:
            try:
                ipaddress.ip_address(host)
                findings.append(Finding(id="raw-ip-link", title="Link uses a raw IP address", severity="high", evidence=link.href))
            except ValueError:
                pass
            if host in SHORTENERS:
                findings.append(Finding(id="shortener-link", title="Link uses a URL shortener", severity="medium", evidence=link.href))
            labels = host.split(".")
            if len(labels) >= 5:
                findings.append(Finding(id="excessive-subdomains", title="Link has many subdomains", severity="medium", evidence=link.href))
            lookalike = _brand_lookalike(host)
            if lookalike:
                findings.append(Finding(id="lookalike-domain", title=f"Domain resembles {lookalike}", severity="high", evidence=f"{host} resembles {lookalike}"))
            seen.add(host)

    for attachment in email.attachments:
        ext = "." + attachment.filename.rsplit(".", 1)[-1].lower() if "." in attachment.filename else ""
        if ext in RISKY_EXTENSIONS:
            findings.append(Finding(id="risky-attachment", title="Potentially risky attachment", severity="high",
                                    evidence=f"{attachment.filename} ({attachment.content_type}, {attachment.size} bytes)"))

    body = (email.text_body + " " + email.html_text).lower()
    matches = [term for term in URGENCY_TERMS if term in body]
    if matches:
        findings.append(Finding(id="urgency-language", title="Urgent or credential related wording", severity="medium",
                                evidence="Matched wording: " + ", ".join(matches)))
    return findings

