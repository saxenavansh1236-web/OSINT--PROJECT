"""
abuse_lookup.py
Checks IP addresses against AbuseIPDB for abuse reports and confidence scores.
Requires a free API key from https://www.abuseipdb.com
Set env var: ABUSEIPDB_API_KEY=your_key
"""

import os
import re
import socket
import requests
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

ABUSE_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSE_BASE    = "https://api.abuseipdb.com/api/v2"


@dataclass
class AbuseResult:
    target:              str  = ""
    ip_address:          str  = ""
    is_public:           bool = True
    abuse_score:         int  = 0
    total_reports:       int  = 0
    distinct_users:      int  = 0
    country_code:        str  = ""
    country_name:        str  = ""
    isp:                 str  = ""
    domain:              str  = ""
    usage_type:          str  = ""
    hostnames:           list = field(default_factory=list)
    is_tor:              bool = False
    is_whitelisted:      bool = False
    last_reported:       str  = ""
    recent_reports:      list = field(default_factory=list)
    flagged:             bool = False
    link:                str  = ""
    error:               Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _normalize_host(target: str) -> str:
    """
    Strip scheme, path, port, query string, and whitespace so we're left
    with just a bare hostname or IP — e.g.
    'https://dgu.ac.in/some/path?x=1' -> 'dgu.ac.in'
    '  Dgu.AC.in  '                   -> 'dgu.ac.in'
    """
    target = (target or "").strip()
    if not target:
        return target

    # If it looks like it has a scheme (http://, https://, ftp://, etc.)
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
    else:
        # No scheme — but there could still be a path/port attached,
        # e.g. "dgu.ac.in/login" or "dgu.ac.in:8080"
        parsed = urlparse(f"//{target}")
        host = parsed.hostname or target.split("/")[0].split(":")[0]

    return host.strip().lower()


def _resolve_to_ip(target: str) -> str:
    """If target is a domain (or a URL containing one), resolve it to an IP."""
    host = _normalize_host(target)

    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, host):
        return host

    try:
        return socket.gethostbyname(host)
    except Exception:
        # Resolution failed — return the cleaned hostname rather than the
        # raw (possibly URL-encoded) input, so the caller/API at least
        # sees a sane value and the error is easier to diagnose.
        return host


def lookup(target: str) -> AbuseResult:
    """
    Check a domain, URL, or IP against AbuseIPDB.
    Domains/URLs are normalized and resolved to an IP before lookup.
    """
    result = AbuseResult(target=target)

    ip = _resolve_to_ip(target)
    result.ip_address = ip
    result.link = f"https://www.abuseipdb.com/check/{ip}"

    if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        result.error = f"Could not resolve '{target}' to a valid IP address"
        return result

    if not ABUSE_API_KEY:
        result.error = "ABUSEIPDB_API_KEY not set"
        return result

    try:
        resp = requests.get(
            f"{ABUSE_BASE}/check",
            headers={
                "Key":    ABUSE_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress":    ip,
                "maxAgeInDays": 90,
                "verbose":      True,
            },
            timeout=15,
        )
        if resp.status_code == 401:
            result.error = "Invalid or unauthorized ABUSEIPDB_API_KEY"
            return result
        if resp.status_code == 422:
            result.error = f"AbuseIPDB rejected the IP address: {ip}"
            return result
        resp.raise_for_status()
        data = resp.json().get("data", {})

        result.is_public        = data.get("isPublic",              True)
        result.abuse_score      = data.get("abuseConfidenceScore",  0)
        result.total_reports    = data.get("totalReports",          0)
        result.distinct_users   = data.get("numDistinctUsers",      0)
        result.country_code     = data.get("countryCode",           "")
        result.isp              = data.get("isp",                   "")
        result.domain           = data.get("domain",                "")
        result.usage_type       = data.get("usageType",             "")
        result.hostnames        = data.get("hostnames",             [])
        result.is_tor           = data.get("isTor",                 False)
        result.is_whitelisted   = data.get("isWhitelisted",         False)
        result.last_reported    = data.get("lastReportedAt",        "") or ""

        country_map = {
            "US": "United States", "IN": "India",   "CN": "China",
            "RU": "Russia",        "DE": "Germany", "GB": "United Kingdom",
            "FR": "France",        "NL": "Netherlands", "BR": "Brazil",
        }
        result.country_name = country_map.get(result.country_code, result.country_code)

        reports = data.get("reports", [])[:5]
        result.recent_reports = [
            {
                "reported_at": r.get("reportedAt",           ""),
                "comment":     r.get("comment",              "")[:200],
                "categories":  r.get("categories",           []),
                "reporter_id": r.get("reporterId",           ""),
                "country":     r.get("reporterCountryCode",  ""),
            }
            for r in reports
        ]

        result.flagged = result.abuse_score > 25 or result.total_reports > 5

    except Exception as e:
        result.error = str(e)

    return result