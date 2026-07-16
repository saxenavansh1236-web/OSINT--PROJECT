"""
headers_analysis.py — HTTP security header audit and server fingerprinting
Checks all OWASP-recommended headers, grades the target, flags issues.
"""

import urllib.request
import urllib.error
import ssl
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Security header definitions ───────────────────────────────────────────
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "HIGH",
        "description": "Forces HTTPS. Missing = downgrade attack possible.",
        "good_value": "max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "HIGH",
        "description": "Prevents XSS by whitelisting content sources.",
        "good_value": "default-src 'self'",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking. Use DENY or SAMEORIGIN.",
        "good_value": "DENY",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Prevents MIME sniffing attacks.",
        "good_value": "nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "description": "Controls referrer info sent with requests.",
        "good_value": "no-referrer-when-downgrade",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "description": "Restricts browser feature access (camera, mic, etc.).",
        "good_value": "geolocation=(), microphone=(), camera=()",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "LOW",
        "description": "Legacy XSS filter (deprecated in modern browsers).",
        "good_value": "1; mode=block",
    },
    "cache-control": {
        "name": "Cache-Control",
        "severity": "LOW",
        "description": "Controls caching of sensitive responses.",
        "good_value": "no-store",
    },
    "cross-origin-embedder-policy": {
        "name": "COEP",
        "severity": "LOW",
        "description": "Prevents cross-origin resource loading without permission.",
        "good_value": "require-corp",
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "severity": "LOW",
        "description": "Isolates browsing context to prevent cross-origin attacks.",
        "good_value": "same-origin",
    },
}

# Headers that leak server info
INFO_LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-wordpress-cache", "via",
    "x-varnish", "x-backend-server", "x-cf-ray",
]

GRADES = [
    (90, "A+"), (80, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")
]


@dataclass
class HeaderCheck:
    header: str
    present: bool
    value: str = ""
    severity: str = ""
    issue: str = ""
    recommendation: str = ""


@dataclass
class HeadersAnalysis:
    target: str
    url: str = ""
    status_code: int = 0
    grade: str = "F"
    score: int = 0                          # 0-100
    security_headers: list = field(default_factory=list)   # HeaderCheck dicts
    missing_headers: list = field(default_factory=list)
    info_leaks: dict = field(default_factory=dict)         # header → value
    server_fingerprint: str = ""
    redirect_chain: list = field(default_factory=list)
    https_enforced: bool = False
    cookies_secure: list = field(default_factory=list)
    cookies_missing_flags: list = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def _make_url(target: str) -> tuple:
    """Return (https_url, http_url) for a target."""
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    return f"https://{target}", f"http://{target}"


def _fetch_headers(url: str, timeout: int = 10) -> tuple:
    """Fetch response headers. Returns (headers_dict, status_code, redirect_chain)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    chain = []
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Security-Audit/1.0)"},
        )
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        with opener.open(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            code    = resp.status
            final   = resp.url
        if final != url:
            chain = [url, final]
        return {k.lower(): v for k, v in headers.items()}, code, chain
    except urllib.error.HTTPError as e:
        return {k.lower(): v for k, v in dict(e.headers).items()}, e.code, chain
    except Exception as e:
        return {}, 0, chain


def _grade(score: int) -> str:
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"


def _analyse_cookies(raw_cookie: str) -> tuple:
    """Returns (secure_cookies, cookies_missing_flags)."""
    secure, missing = [], []
    for cookie in raw_cookie.split(","):
        name_match = re.match(r"\s*([^=]+)=", cookie)
        name = name_match.group(1).strip() if name_match else "cookie"
        flags = cookie.lower()
        issues = []
        if "httponly" not in flags:
            issues.append("Missing HttpOnly")
        if "secure" not in flags:
            issues.append("Missing Secure flag")
        if "samesite" not in flags:
            issues.append("Missing SameSite")
        if issues:
            missing.append({"name": name, "issues": issues})
        else:
            secure.append(name)
    return secure, missing


def inspect(target: str) -> HeadersAnalysis:
    """
    Main entry point. Fetches headers and performs full security audit.
    """
    https_url, http_url = _make_url(target)
    result = HeadersAnalysis(target=target, url=https_url)

    # ── Try HTTPS first, fall back to HTTP ────────────────────────────────
    headers, code, chain = _fetch_headers(https_url)
    if not headers:
        headers, code, chain = _fetch_headers(http_url)
        result.url = http_url
    else:
        result.https_enforced = True

    if not headers:
        result.error = "Could not connect to target."
        return result

    result.status_code  = code
    result.redirect_chain = chain

    # ── Security headers audit ─────────────────────────────────────────────
    score = 0
    sec_results = []
    missing = []

    weights = {
        "HIGH": 25, "MEDIUM": 15, "LOW": 5
    }

    for header_key, meta in SECURITY_HEADERS.items():
        present = header_key in headers
        value   = headers.get(header_key, "")
        severity = meta["severity"]

        if present:
            score += weights.get(severity, 5)
            sec_results.append(HeaderCheck(
                header=meta["name"], present=True, value=value,
                severity=severity, issue="", recommendation=""
            ))
        else:
            missing.append(HeaderCheck(
                header=meta["name"], present=False, value="",
                severity=severity,
                issue=meta["description"],
                recommendation=f"Add: {header_key}: {meta['good_value']}"
            ))

    # Cap at 100
    score = min(score, 100)
    result.score = score
    result.grade = _grade(score)
    result.security_headers = [asdict(h) for h in sec_results]
    result.missing_headers  = [asdict(h) for h in missing]

    # ── Info leakage ──────────────────────────────────────────────────────
    for h in INFO_LEAK_HEADERS:
        if h in headers:
            result.info_leaks[h] = headers[h]

    # ── Server fingerprint ────────────────────────────────────────────────
    parts = []
    if "server" in headers:
        parts.append(headers["server"])
    if "x-powered-by" in headers:
        parts.append(headers["x-powered-by"])
    result.server_fingerprint = " | ".join(parts) if parts else "Hidden"

    # ── Cookie analysis ────────────────────────────────────────────────────
    raw_cookie = headers.get("set-cookie", "")
    if raw_cookie:
        result.cookies_secure, result.cookies_missing_flags = _analyse_cookies(raw_cookie)

    # ── HTTPS enforcement check ───────────────────────────────────────────
    if chain and chain[0].startswith("http://") and chain[-1].startswith("https://"):
        result.https_enforced = True

    # ── Summary ───────────────────────────────────────────────────────────
    result.summary = (
        f"Grade {result.grade} ({result.score}/100). "
        f"{len(sec_results)} security headers present, "
        f"{len(missing)} missing. "
        f"{len(result.info_leaks)} info-leaking headers detected."
    )

    return result