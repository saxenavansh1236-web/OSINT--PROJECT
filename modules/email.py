"""
email_osint.py — Deep email intelligence.

Features
--------
* Domain extraction & validation
* MX record lookup (via dns_lookup)
* Disposable email detection (blocklist + API)
* Gravatar profile check
* Breach lookup (via breach.py)
* SMTP existence probe (non-intrusive)
* Email reputation score
"""

from __future__ import annotations

import hashlib
import re
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional

import requests

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "OSINT-Platform/2.0"})
_TIMEOUT = 8

# ── Known disposable email domains (top offenders) ──────────────────────────
_DISPOSABLE_DOMAINS: set[str] = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwaway.email", "yopmail.com", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "spam4.me", "dispostable.com", "mailnull.com", "spamgourmet.com",
    "trashmail.at", "trashmail.io", "trashmail.me", "tempr.email",
    "fakeinbox.com", "maildrop.cc", "spamfree24.org", "discard.email",
    "getnada.com", "anonaddy.com", "spamtrap.ro", "binkmail.com",
    "safetymail.info", "tempinbox.com", "mohmal.com", "mintemail.com",
}


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class EmailResult:
    email: str
    valid_format: bool
    domain: str
    username: str
    disposable: bool
    disposable_source: str          # "local_list" | "api" | ""
    mx_records: list[str]
    has_mx: bool
    gravatar_url: str               # "" if not found
    gravatar_profile: dict          # {} if not found
    smtp_exists: Optional[bool]     # None = not probed / inconclusive
    reputation: str                 # "clean" | "suspicious" | "malicious" | "unknown"
    reputation_details: dict
    breaches: list[dict]            # from breach.py BreachResult.to_dict()
    score: int                      # 0–100  (100 = most trustworthy)
    flags: list[str]                # human-readable warning list

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def investigate(email: str, *, check_breaches: bool = True) -> EmailResult:
    """
    Full email OSINT.  Returns EmailResult.
    Set check_breaches=False to skip the breach-lookup step.
    """
    email = email.strip().lower()
    flags: list[str] = []

    # 1. Format
    valid, username, domain = _parse(email)
    if not valid:
        flags.append("Invalid email format")

    # 2. Disposable check
    disposable, disp_source = _check_disposable(domain)
    if disposable:
        flags.append(f"Disposable email domain ({disp_source})")

    # 3. MX records
    mx = _get_mx(domain)
    has_mx = bool(mx)
    if not has_mx:
        flags.append("Domain has no MX records — cannot receive email")

    # 4. Gravatar
    grav_url, grav_profile = _gravatar(email)

    # 5. Reputation (EmailRep)
    rep, rep_details = _emailrep(email)
    if rep in ("suspicious", "malicious"):
        flags.append(f"Email reputation: {rep}")

    # 6. SMTP probe (only if domain has MX)
    smtp_exists: Optional[bool] = None
    if has_mx and mx:
        smtp_exists = _smtp_probe(email, mx[0])

    # 7. Breaches
    breach_results: list[dict] = []
    if check_breaches:
        try:
            from breach import check as breach_check
            breach_results = [b.to_dict() if hasattr(b, "to_dict") else b
                              for b in breach_check(email)]
            if breach_results:
                flags.append(f"Found in {len(breach_results)} breach(es)")
        except ImportError:
            pass

    # 8. Compute trust score
    score = _score(valid, disposable, has_mx, smtp_exists, rep, breach_results, grav_url)

    return EmailResult(
        email=email,
        valid_format=valid,
        domain=domain,
        username=username,
        disposable=disposable,
        disposable_source=disp_source,
        mx_records=mx,
        has_mx=has_mx,
        gravatar_url=grav_url,
        gravatar_profile=grav_profile,
        smtp_exists=smtp_exists,
        reputation=rep,
        reputation_details=rep_details,
        breaches=breach_results,
        score=score,
        flags=flags,
    )


def extract_domain(email: str) -> str:
    """Quick helper — returns the domain part of an email."""
    _, _, domain = _parse(email.strip().lower())
    return domain


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _parse(email: str) -> tuple[bool, str, str]:
    if "@" not in email or not _EMAIL_RE.match(email):
        parts = email.split("@", 1)
        return False, parts[0] if parts else "", parts[1] if len(parts) > 1 else ""
    user, domain = email.split("@", 1)
    return True, user, domain


def _check_disposable(domain: str) -> tuple[bool, str]:
    if domain in _DISPOSABLE_DOMAINS:
        return True, "local_list"
    # API check via open.kickbox.com
    try:
        r = _SESSION.get(f"https://open.kickbox.com/v1/disposable/{domain}", timeout=_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if data.get("disposable"):
                return True, "kickbox_api"
    except Exception:
        pass
    return False, ""


def _get_mx(domain: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return sorted(
            [str(r.exchange).rstrip(".") for r in answers],
            key=lambda x: answers[0].preference,
        )
    except Exception:
        return []


def _gravatar(email: str) -> tuple[str, dict]:
    """Check Gravatar by email MD5 hash."""
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    avatar_url = f"https://www.gravatar.com/avatar/{md5}?d=404"
    profile_url = f"https://www.gravatar.com/{md5}.json"
    try:
        # Check if avatar exists
        r = _SESSION.get(avatar_url, timeout=_TIMEOUT, allow_redirects=False)
        if r.status_code == 404:
            return "", {}
        # Try to fetch profile JSON
        rp = _SESSION.get(profile_url, timeout=_TIMEOUT)
        if rp.status_code == 200:
            profile_data = rp.json().get("entry", [{}])[0]
            return avatar_url, {
                "display_name":   profile_data.get("displayName", ""),
                "profile_url":    profile_data.get("profileUrl", ""),
                "about_me":       profile_data.get("aboutMe", ""),
                "location":       profile_data.get("currentLocation", ""),
                "accounts":       [a.get("name") for a in profile_data.get("accounts", [])],
            }
        return avatar_url, {}
    except Exception:
        return "", {}


def _emailrep(email: str) -> tuple[str, dict]:
    try:
        r = _SESSION.get(f"https://emailrep.io/{email}", timeout=_TIMEOUT)
        if r.status_code != 200:
            return "unknown", {}
        data = r.json()
        details = data.get("details", {})
        rep = data.get("reputation", "unknown")
        return rep, {
            "suspicious":         data.get("suspicious", False),
            "references":         details.get("references", 0),
            "blacklisted":        details.get("blacklisted", False),
            "malicious_activity": details.get("malicious_activity", False),
            "spam":               details.get("spam", False),
            "data_breach":        details.get("data_breach", False),
            "days_since_breach":  details.get("days_since_domain_breach", None),
            "profiles":           details.get("profiles", []),
        }
    except Exception:
        return "unknown", {}


def _smtp_probe(email: str, mx_host: str) -> Optional[bool]:
    """
    Non-intrusive SMTP RCPT probe.
    Connects, says EHLO, sends MAIL FROM / RCPT TO, reads response.
    Does NOT send any email.
    """
    try:
        import smtplib
        with smtplib.SMTP(timeout=6) as s:
            s.connect(mx_host, 25)
            s.ehlo("osint-probe.local")
            s.mail("probe@osint-probe.local")
            code, _ = s.rcpt(email)
            return code == 250
    except Exception:
        return None


def _score(valid, disposable, has_mx, smtp_exists, reputation, breaches, gravatar_url) -> int:
    score = 100
    if not valid:        score -= 40
    if disposable:       score -= 25
    if not has_mx:       score -= 20
    if smtp_exists is False: score -= 15
    if reputation == "malicious":   score -= 30
    if reputation == "suspicious":  score -= 15
    score -= min(len(breaches) * 5, 25)
    if gravatar_url:     score += 5   # social presence = slight trust signal
    return max(0, min(100, score))