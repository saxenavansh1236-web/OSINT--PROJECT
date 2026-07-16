"""
certificate_history.py — Historical SSL certificate analysis via Certificate Transparency logs
Source: crt.sh (free, no API key required)
"""

import urllib.request
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class CertRecord:
    common_name: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    serial: str = ""
    san_domains: list = field(default_factory=list)
    is_wildcard: bool = False
    is_expired: bool = False
    log_id: str = ""


@dataclass
class CertificateHistory:
    domain: str
    total_certs: int = 0
    certificates: list = field(default_factory=list)     # CertRecord dicts
    all_domains_seen: list = field(default_factory=list)  # all SANs ever seen
    wildcard_certs: int = 0
    issuers: list = field(default_factory=list)           # unique issuers
    expired_count: int = 0
    active_count: int = 0
    earliest_cert: str = ""
    latest_cert: str = ""
    subdomains_discovered: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def _fetch_crtsh(domain: str) -> list:
    """Query crt.sh JSON API for CT log entries."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json&deduplicate=Y"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "OSINT-Research/1.0",
                     "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception:
        return []


def _is_expired(not_after: str) -> bool:
    try:
        exp = datetime.strptime(not_after[:10], "%Y-%m-%d")
        return exp < datetime.utcnow()
    except Exception:
        return False


def _extract_sans(name_value: str) -> list:
    """Split common_name / name_value field into individual SANs."""
    if not name_value:
        return []
    return [s.strip() for s in name_value.split("\n") if s.strip()]


def lookup(domain: str, max_certs: int = 50) -> CertificateHistory:
    """
    Main entry point.
    Fetches certificate history from crt.sh Certificate Transparency logs.
    """
    domain = domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
    result = CertificateHistory(domain=domain)

    raw = _fetch_crtsh(domain)
    if not raw:
        result.error = "No CT log data found or crt.sh unavailable."
        return result

    certs = []
    all_domains: set = set()
    issuers: set = set()
    dates = []

    for entry in raw[:max_certs]:
        not_before = str(entry.get("not_before", ""))[:10]
        not_after  = str(entry.get("not_after",  ""))[:10]
        issuer_cn  = entry.get("issuer_name", "")
        cn         = entry.get("common_name", "")
        name_val   = entry.get("name_value", cn)

        # Clean issuer to just CN
        issuer_match = re.search(r"CN=([^,]+)", issuer_cn)
        issuer_clean = issuer_match.group(1).strip() if issuer_match else issuer_cn[:60]

        sans = _extract_sans(name_val)
        expired = _is_expired(not_after)
        is_wildcard = any("*" in s for s in sans) or "*" in cn

        cert = CertRecord(
            common_name=cn,
            issuer=issuer_clean,
            not_before=not_before,
            not_after=not_after,
            serial=str(entry.get("serial_number", "")),
            san_domains=sans,
            is_wildcard=is_wildcard,
            is_expired=expired,
            log_id=str(entry.get("id", "")),
        )
        certs.append(asdict(cert))

        # Collect all unique domains seen across all certs
        for s in sans:
            if s and s != domain:
                all_domains.add(s.lstrip("*."))

        if issuer_clean:
            issuers.add(issuer_clean)
        if not_before:
            dates.append(not_before)

    # Sort certs by date (newest first)
    certs.sort(key=lambda c: c.get("not_before", ""), reverse=True)

    result.total_certs   = len(certs)
    result.certificates  = certs
    result.wildcard_certs = sum(1 for c in certs if c.get("is_wildcard"))
    result.expired_count  = sum(1 for c in certs if c.get("is_expired"))
    result.active_count   = result.total_certs - result.expired_count
    result.issuers        = sorted(issuers)

    # Subdomains discovered via SANs (excluding wildcards)
    subs = sorted({d for d in all_domains
                   if d.endswith(f".{domain}") and "*" not in d})
    result.subdomains_discovered = subs
    result.all_domains_seen = sorted(all_domains)

    if dates:
        dates.sort()
        result.earliest_cert = dates[0]
        result.latest_cert   = dates[-1]

    return result