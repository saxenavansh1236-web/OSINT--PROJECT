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
    """A single breach / leak finding."""
    source:       str
    breach_name:  str
    target:       str
    target_type:  str
    date:         str
    records:      int
    data_classes: list[str]
    severity:     str
    description:  str
    verified:     bool = False

    @property
    def name(self) -> str:
        return self.breach_name

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LeakReport:
    target:           str
    target_type:      str
    total_leaks:      int
    sources_checked:  list[str]
    severity_summary: dict
    leaks:            list[LeakEntry] = field(default_factory=list)
    password_pwned:   bool = False
    password_count:   int  = 0
    error:            str  = ""
    # NEW: set when the caller asked for one type but the target actually
    # looked like another (e.g. breach_check("google.com") called via the
    # email alias) and this module auto-corrected the check performed.
    type_corrected_from: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["leaks"] = [asdict(l) for l in self.leaks]
        return d


# ─────────────────────────────────────────────
# Type-detection helpers (used both for "auto" and for self-correction)
# ─────────────────────────────────────────────

def _looks_like_email(target: str) -> bool:
    return "@" in target and "." in target.split("@")[-1]


def _looks_like_phone(target: str) -> bool:
    cleaned = re.sub(r"[\s\-().]+", "", target)
    return bool(re.match(r"^\+?\d{7,15}$", cleaned))


def _looks_like_domain(target: str) -> bool:
    return "." in target and not _looks_like_email(target) and not _looks_like_phone(target)


def _detect_type(target: str) -> str:
    if _looks_like_email(target):
        return "email"
    if _looks_like_phone(target):
        return "phone"
    if _looks_like_domain(target):
        return "domain"
    return "username"


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
    """Check *target* across all available leak databases."""
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


# ── Convenience wrappers — NOW SELF-CORRECTING ────────────────────────────
#
# app.py's run_osint_scan() calls `breach_check(target)` (aliased to
# check_email) for EVERY target regardless of actual type. Previously this
# meant domains/usernames/phones were silently forced through the email
# pipeline, producing meaningless broad matches. Each wrapper below now
# checks whether the target actually looks like its claimed type before
# proceeding, and routes to the correct checker if not — so misuse from
# the caller no longer produces a misleading result.

def check_email(email: str) -> LeakReport:
    if not _looks_like_email(email):
        real_type = _detect_type(email)
        report = check_all(email, real_type)  # type: ignore[arg-type]
        report.type_corrected_from = "email"
        return report
    return check_all(email, "email")


def check_username(user: str) -> LeakReport:
    # Usernames are the fallback bucket in _detect_type, so no strong
    # positive check is possible here — but if it's clearly an email or
    # domain, correct anyway rather than treating it as a bare username.
    if _looks_like_email(user):
        report = check_all(user, "email")
        report.type_corrected_from = "username"
        return report
    if _looks_like_domain(user):
        report = check_all(user, "domain")
        report.type_corrected_from = "username"
        return report
    return check_all(user, "username")


def check_domain(domain: str) -> LeakReport:
    if not _looks_like_domain(domain):
        real_type = _detect_type(domain)
        report = check_all(domain, real_type)  # type: ignore[arg-type]
        report.type_corrected_from = "domain"
        return report
    return check_all(domain, "domain")


def check_phone(phone: str) -> LeakReport:
    if not _looks_like_phone(phone):
        real_type = _detect_type(phone)
        report = check_all(phone, real_type)  # type: ignore[arg-type]
        report.type_corrected_from = "phone"
        return report
    return check_all(phone, "phone")


def check_password(password: str) -> dict:
    """k-anonymity pwned-passwords check (never sends the full password)."""
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
    """
    LeakCheck.io public API — designed for email/username/phone/hash
    lookups. When called with ttype != "email"/"phone"/"username" (i.e.
    a domain, per _check_domain below), results are inherently broad/
    unverified matches rather than confirmed hits on a real mailbox, and
    are labeled accordingly by the caller — see _check_domain().
    """
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

# Well-known organizational/company domains as bare strings shouldn't be
# probed as social-media usernames — "google.com found on Snapchat" is
# noise, not a finding. Skip username checks entirely if the target looks
# like a domain (has a TLD-shaped suffix), since a real username almost
# never contains a dot + valid TLD.
def _looks_like_bare_domain(username: str) -> bool:
    return bool(re.match(r"^[a-z0-9-]+\.[a-z]{2,}$", username, re.IGNORECASE))


def _check_username(username: str, sources: list[str]) -> list[LeakEntry]:
    if _looks_like_bare_domain(username):
        sources.append("Social platforms (skipped — target looks like a domain, not a username)")
        return []

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
    """
    Domain-wide leak lookup. LeakCheck.io's public API isn't built for
    domain-scoped queries — a hit here means the string appeared somewhere
    in their index, not that a specific mailbox @domain was confirmed
    breached. Results are relabeled "medium" severity (down from the
    "high" _leakcheck() would normally set), explicitly marked as an
    unverified domain-wide match, and capped to the top 15 so one noisy
    response can't flood the risk score or the report with 40+ entries.
    """
    results: list[LeakEntry] = []
    sources.append("LeakCheck.io (domain — unverified, broad match)")

    raw = _leakcheck(domain, "domain")
    for entry in raw[:15]:
        entry.severity = "medium"
        entry.description = (
            f"Domain-wide unverified match for '{domain}' in "
            f"{entry.breach_name} (LeakCheck.io) — not confirmed against a "
            f"specific mailbox; treat as a low-confidence lead only."
        )
        results.append(entry)

    if INTELX_KEY:
        intelx_results = _intelx(domain, "domain")
        for entry in intelx_results:
            entry.severity = "medium"
        results.extend(intelx_results)
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
