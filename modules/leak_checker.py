"""
leak_checker.py — Unified leak / breach checker for any target type.
Supersedes breach.py entirely.

Combines email, username, domain, and phone checks into one interface.
Aggregates results from all available sources and deduplicates.

Usage
-----
    from leak_checker import check_all, check_email, check_username, check_password

    results = check_all("john@example.com")
    results = check_all("+14155552671", target_type="phone")
    results = check_all("johndoe", target_type="username")

    # Password k-anonymity (replaces breach.check_password)
    pw = check_password("hunter2")
    # → {"pwned": True, "count": 34821}

Migration from breach.py
------------------------
    # OLD
    from breach import check, check_password
    results = check("user@example.com")       # returned list[BreachResult]
    pw      = check_password("secret")        # returned {"pwned": bool, "count": int}

    # NEW
    from leak_checker import check_email, check_password
    report  = check_email("user@example.com") # returns LeakReport
    results = report.leaks                    # list[LeakEntry]  (same shape as BreachResult)
    pw      = check_password("secret")        # identical return shape
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Literal

import requests

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "OSINT-Platform/2.0"})
_TIMEOUT = 10

HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")
INTELX_KEY   = os.environ.get("INTELX_API_KEY", "")

TargetType = Literal["email", "username", "domain", "phone", "auto"]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3, "unknown": 4, "error": 5}


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class LeakEntry:
    """
    A single breach / leak finding.
    Drop-in replacement for breach.BreachResult — field names are a superset.
    """
    source:       str
    breach_name:  str          # was "name" in BreachResult
    target:       str
    target_type:  str
    date:         str
    records:      int
    data_classes: list[str]
    severity:     str          # critical | high | medium | info | unknown | error
    description:  str
    verified:     bool = False  # True if from a curated / authoritative source

    # ── breach.BreachResult compatibility shim ──────────────────────────────
    @property
    def name(self) -> str:
        """Alias kept for drop-in compatibility with breach.BreachResult consumers."""
        return self.breach_name

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LeakReport:
    target:           str
    target_type:      str
    total_leaks:      int
    sources_checked:  list[str]
    severity_summary: dict       # {"critical": 2, "high": 3, …}
    leaks:            list[LeakEntry] = field(default_factory=list)
    password_pwned:   bool = False
    password_count:   int  = 0
    error:            str  = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["leaks"] = [asdict(l) for l in self.leaks]
        return d


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def check_all(
    target: str,
    target_type: TargetType = "auto",
    *,
    check_pw: bool = False,
    password: str = "",
) -> LeakReport:
    """
    Check *target* across all available leak databases.

    Args:
        target:      Email, username, domain, or phone number.
        target_type: Explicit type or "auto" to detect.
        check_pw:    Also check a password via k-anonymity.
        password:    Plaintext password (never sent to any API).

    Returns LeakReport with all findings.
    """
    target = target.strip().lower()
    ttype  = target_type if target_type != "auto" else _detect_type(target)

    report = LeakReport(
        target=target,
        target_type=ttype,
        total_leaks=0,
        sources_checked=[],
        severity_summary={"critical": 0, "high": 0, "medium": 0, "info": 0},
    )

    leaks: list[LeakEntry] = []

    if ttype == "email":
        leaks.extend(_check_email(target, report.sources_checked))
    elif ttype == "username":
        leaks.extend(_check_username(target, report.sources_checked))
    elif ttype == "domain":
        leaks.extend(_check_domain(target, report.sources_checked))
    elif ttype == "phone":
        leaks.extend(_check_phone(target, report.sources_checked))

    report.leaks      = _dedupe_sort(leaks)
    report.total_leaks = len(report.leaks)

    for l in report.leaks:
        sev = l.severity if l.severity in report.severity_summary else "info"
        report.severity_summary[sev] = report.severity_summary.get(sev, 0) + 1

    if check_pw and password:
        pwned, count = _hibp_password(password)
        report.password_pwned  = pwned
        report.password_count  = count
        report.sources_checked.append("HaveIBeenPwned (passwords)")

    return report


# ── Convenience wrappers ──────────────────────────────────────────────────────

def check_email(email: str)   -> LeakReport: return check_all(email,  "email")
def check_username(user: str) -> LeakReport: return check_all(user,   "username")
def check_domain(domain: str) -> LeakReport: return check_all(domain, "domain")
def check_phone(phone: str)   -> LeakReport: return check_all(phone,  "phone")


def check_password(password: str) -> dict:
    """
    k-anonymity pwned-passwords check (never sends the full password).
    Returns {"pwned": bool, "count": int}.

    Replaces breach.check_password() — identical return shape.
    """
    pwned, count = _hibp_password(password)
    return {"pwned": pwned, "count": count}


# ─────────────────────────────────────────────
# Email checkers
# ─────────────────────────────────────────────

def _check_email(email: str, sources: list[str]) -> list[LeakEntry]:
    results: list[LeakEntry] = []

    if HIBP_API_KEY:
        results.extend(_hibp_email(email))
        sources.append("HaveIBeenPwned")

    results.extend(_leakcheck(email, "email"))
    sources.append("LeakCheck.io")

    results.extend(_emailrep(email))
    sources.append("EmailRep.io")

    if INTELX_KEY:
        results.extend(_intelx(email, "email"))
        sources.append("IntelX")

    results.extend(_breach_directory(email))
    sources.append("Breach.directory")

    return results


def _hibp_email(email: str) -> list[LeakEntry]:
    try:
        r = _SESSION.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": "OSINT-Platform/2.0"},
            params={"truncateResponse": "false"},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return []
        r.raise_for_status()
        out = []
        for b in r.json():
            classes = b.get("DataClasses", [])
            sev = "critical" if any(
                c in classes for c in ("Passwords", "Credit Cards", "Bank Account Numbers", "Social Security Numbers")
            ) else "high"
            out.append(LeakEntry(
                source="HaveIBeenPwned",
                breach_name=b.get("Name", "Unknown"),
                target=email, target_type="email",
                date=b.get("BreachDate", "Unknown"),
                records=b.get("PwnCount", 0),
                data_classes=classes,
                severity=sev,
                description=f"{b.get('Title', '')} — {b.get('PwnCount', 0):,} accounts",
                verified=True,
            ))
        return out
    except Exception as exc:
        return [_error_entry("HaveIBeenPwned", email, str(exc))]


def _leakcheck(target: str, ttype: str) -> list[LeakEntry]:
    try:
        r = _SESSION.get(
            "https://leakcheck.io/api/public",
            params={"check": target},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if not data.get("success") or not data.get("found"):
            return []
        return [LeakEntry(
            source="LeakCheck.io",
            breach_name=s.get("name", "Unknown"),
            target=target, target_type=ttype,
            date=s.get("date", "Unknown"),
            records=0,
            data_classes=s.get("data", []),
            severity="high",
            description=f"Found in {s.get('name', 'unknown')} (LeakCheck.io)",
            verified=False,
        ) for s in data.get("sources", [])]
    except Exception:
        return []


def _emailrep(email: str) -> list[LeakEntry]:
    if "@" not in email:
        return []
    try:
        r = _SESSION.get(f"https://emailrep.io/{email}", timeout=_TIMEOUT)
        r.raise_for_status()
        details = r.json().get("details", {})
        entries = []
        if details.get("data_breach"):
            entries.append(LeakEntry(
                source="EmailRep.io", breach_name="Unknown breach",
                target=email, target_type="email",
                date="Unknown", records=0, data_classes=[],
                severity="medium",
                description="Address appears in at least one breach (EmailRep.io)",
                verified=False,
            ))
        if details.get("malicious_activity"):
            entries.append(LeakEntry(
                source="EmailRep.io", breach_name="Malicious activity",
                target=email, target_type="email",
                date="Unknown", records=0, data_classes=["Malicious use"],
                severity="critical",
                description="Malicious activity detected (EmailRep.io)",
                verified=False,
            ))
        if details.get("spam"):
            entries.append(LeakEntry(
                source="EmailRep.io", breach_name="Spam address",
                target=email, target_type="email",
                date="Unknown", records=0, data_classes=["Spam"],
                severity="info",
                description="Address is associated with spam activity (EmailRep.io)",
                verified=False,
            ))
        return entries
    except Exception:
        return []


def _intelx(target: str, ttype: str) -> list[LeakEntry]:
    """
    IntelX paste-index search.
    Shared by email, domain, phone checks — and also called by paste_monitor
    to avoid duplicating IntelX logic there.
    """
    key = INTELX_KEY or "sbtguard:demo"
    try:
        r = _SESSION.post(
            "https://2.intelx.io/intelligent/search",
            json={"term": target, "maxresults": 5, "media": 0, "target": 0},
            headers={"x-key": key},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        search_id = r.json().get("id", "")
        if not search_id:
            return []
        time.sleep(2)
        r2 = _SESSION.get(
            "https://2.intelx.io/intelligent/search/result",
            params={"id": search_id, "limit": 5},
            headers={"x-key": key},
            timeout=_TIMEOUT,
        )
        r2.raise_for_status()
        records = r2.json().get("records", [])
        return [LeakEntry(
            source="IntelX",
            breach_name=rec.get("name", "Paste / leak"),
            target=target, target_type=ttype,
            date=str(rec.get("date", "Unknown"))[:10],
            records=0,
            data_classes=["Paste"],
            severity="high",
            description=f"Target found in IntelX paste index: {rec.get('name', 'unknown')}",
            verified=False,
        ) for rec in records]
    except Exception:
        return []


def _breach_directory(email: str) -> list[LeakEntry]:
    if "@" not in email:
        return []
    try:
        sha1 = hashlib.sha1(email.encode()).hexdigest()[:8]
        r = _SESSION.get(
            f"https://breach.directory/api/lookup?query={sha1}",
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            return []
        return [LeakEntry(
            source="Breach.directory",
            breach_name=e.get("source", "Unknown"),
            target=email, target_type="email",
            date=e.get("date", "Unknown"),
            records=0,
            data_classes=e.get("fields", []),
            severity="high",
            description=f"Match in {e.get('source', 'unknown')} (Breach.directory)",
            verified=False,
        ) for e in r.json().get("found", [])[:5]]
    except Exception:
        return []


# ─────────────────────────────────────────────
# Username checker
# ─────────────────────────────────────────────

_USERNAME_SITES: list[tuple[str, str, str]] = [
    ("GitHub",      "https://github.com/{}",                   '"login":'),
    ("Twitter/X",   "https://twitter.com/{}",                  "og:title"),
    ("Instagram",   "https://www.instagram.com/{}/",           '"username":'),
    ("Reddit",      "https://www.reddit.com/user/{}/about.json", '"name":'),
    ("TikTok",      "https://www.tiktok.com/@{}",              "UniqueId"),
    ("LinkedIn",    "https://www.linkedin.com/in/{}/",         "og:title"),
    ("YouTube",     "https://www.youtube.com/@{}",             "channelId"),
    ("Twitch",      "https://www.twitch.tv/{}",                "og:title"),
    ("Pinterest",   "https://www.pinterest.com/{}/",           "og:title"),
    ("Snapchat",    "https://www.snapchat.com/add/{}",         "og:title"),
    ("Telegram",    "https://t.me/{}",                         "og:title"),
    ("Medium",      "https://medium.com/@{}",                  "og:title"),
    ("Dev.to",      "https://dev.to/{}",                       "og:title"),
    ("Patreon",     "https://www.patreon.com/{}",              "og:title"),
    ("Mastodon",    "https://mastodon.social/@{}",             "og:title"),
    ("Keybase",     "https://keybase.io/{}",                   '"username":'),
    ("Gravatar",    "https://www.gravatar.com/{}",             "og:title"),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}", "created:"),
    ("ProductHunt", "https://www.producthunt.com/@{}",         "og:title"),
    ("Behance",     "https://www.behance.net/{}",              "og:title"),
    ("Dribbble",    "https://dribbble.com/{}",                 "og:title"),
    ("GitLab",      "https://gitlab.com/{}",                   "og:title"),
    ("Codepen",     "https://codepen.io/{}",                   "og:title"),
    ("Replit",      "https://replit.com/@{}",                  "og:title"),
    ("HuggingFace", "https://huggingface.co/{}",               "og:title"),
]


def _check_username(username: str, sources: list[str]) -> list[LeakEntry]:
    sources.append("Social platforms (25 sites)")
    found: list[LeakEntry] = []

    def probe(site_name: str, url_tmpl: str, indicator: str) -> LeakEntry | None:
        url = url_tmpl.format(username)
        try:
            r = _SESSION.get(url, timeout=8, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and indicator.lower() in r.text.lower():
                return LeakEntry(
                    source=site_name,
                    breach_name=f"Profile found: {url}",
                    target=username, target_type="username",
                    date="", records=0, data_classes=["Username"],
                    severity="info",
                    description=f"Username @{username} found on {site_name}: {url}",
                    verified=True,
                )
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(probe, s, u, i) for s, u, i in _USERNAME_SITES]
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return found


# ─────────────────────────────────────────────
# Domain & phone checkers
# ─────────────────────────────────────────────

def _check_domain(domain: str, sources: list[str]) -> list[LeakEntry]:
    results: list[LeakEntry] = []
    sources.append("LeakCheck.io (domain)")
    results.extend(_leakcheck(domain, "domain"))
    if INTELX_KEY:
        results.extend(_intelx(domain, "domain"))
        sources.append("IntelX (domain)")
    return results


def _check_phone(phone: str, sources: list[str]) -> list[LeakEntry]:
    results: list[LeakEntry] = []
    sources.append("LeakCheck.io (phone)")
    results.extend(_leakcheck(phone, "phone"))
    if INTELX_KEY:
        results.extend(_intelx(phone, "phone"))
        sources.append("IntelX (phone)")
    return results


# ─────────────────────────────────────────────
# Password k-anonymity
# ─────────────────────────────────────────────

def _hibp_password(password: str) -> tuple[bool, int]:
    sha1   = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = _SESSION.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        for line in r.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True, int(count)
        return False, 0
    except Exception:
        return False, 0


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _detect_type(target: str) -> str:
    if "@" in target and "." in target.split("@")[-1]:
        return "email"
    if target.startswith("+") or (target.isdigit() and len(target) >= 7):
        return "phone"
    if "." in target and not target.startswith("+"):
        return "domain"
    return "username"


def _error_entry(source: str, target: str, msg: str) -> LeakEntry:
    return LeakEntry(
        source=source, breach_name="Error",
        target=target, target_type="unknown",
        date="Unknown", records=0, data_classes=[],
        severity="error", description=msg,
    )


def _dedupe_sort(entries: list[LeakEntry]) -> list[LeakEntry]:
    seen: set[tuple] = set()
    unique: list[LeakEntry] = []
    for e in entries:
        key = (e.source.lower(), e.breach_name.lower())
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return sorted(unique, key=lambda e: _SEV_ORDER.get(e.severity, 99))