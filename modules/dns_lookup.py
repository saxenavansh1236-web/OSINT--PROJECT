"""
dns_lookup.py — Comprehensive DNS record collector.

Collects: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR
Parses:   SPF (from TXT), DMARC (from _dmarc TXT), DKIM probes
Extras:   Zone transfer attempt, DNSSEC check, wildcard detection
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.exception


_LIFETIME = 6   # seconds per query


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class DNSResult:
    domain: str
    a:          list[str] = field(default_factory=list)   # IPv4
    aaaa:       list[str] = field(default_factory=list)   # IPv6
    mx:         list[dict] = field(default_factory=list)  # [{priority, host}]
    ns:         list[str] = field(default_factory=list)   # name servers
    txt:        list[str] = field(default_factory=list)   # all TXT records
    cname:      list[str] = field(default_factory=list)
    soa:        dict = field(default_factory=dict)        # {mname, rname, serial, refresh, …}
    caa:        list[dict] = field(default_factory=list)  # [{flag, tag, value}]
    ptr:        list[str] = field(default_factory=list)   # reverse DNS for each A record
    # Parsed / derived
    spf:        dict = field(default_factory=dict)        # {raw, mechanisms, all_policy}
    dmarc:      dict = field(default_factory=dict)        # {raw, policy, rua, ruf, …}
    dkim_selectors: list[str] = field(default_factory=list)  # found selectors
    dnssec:     bool = False
    wildcard:   bool = False
    zone_transfer: list[str] = field(default_factory=list)  # records if AXFR succeeds
    errors:     dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def lookup(domain: str) -> DNSResult:
    """Full DNS enumeration for *domain*. Returns DNSResult."""
    domain = _clean(domain)
    result = DNSResult(domain=domain)

    result.a     = _query(domain, "A")
    result.aaaa  = _query(domain, "AAAA")
    result.ns    = _query(domain, "NS")
    result.cname = _query(domain, "CNAME")
    result.txt   = _query(domain, "TXT")
    result.mx    = _query_mx(domain)
    result.soa   = _query_soa(domain)
    result.caa   = _query_caa(domain)

    # Reverse DNS for each A record
    result.ptr = [_ptr(ip) for ip in result.a]

    # Parse SPF & DMARC from TXT
    result.spf   = _parse_spf(result.txt)
    result.dmarc = _query_dmarc(domain)

    # DKIM probes (common selectors)
    result.dkim_selectors = _probe_dkim(domain)

    # DNSSEC
    result.dnssec = _check_dnssec(domain)

    # Wildcard detection
    result.wildcard = _check_wildcard(domain)

    # Zone transfer attempt (rarely works, but worth trying)
    result.zone_transfer = _zone_transfer(domain, result.ns)

    return result


# ─────────────────────────────────────────────
# Record queries
# ─────────────────────────────────────────────

def _query(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=_LIFETIME)
        if rtype in ("A", "AAAA"):
            return [str(r) for r in answers]
        if rtype == "NS":
            return sorted([str(r.target).rstrip(".") for r in answers])
        if rtype == "CNAME":
            return [str(r.target).rstrip(".") for r in answers]
        if rtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
        return [str(r) for r in answers]
    except Exception:
        return []


def _query_mx(domain: str) -> list[dict]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=_LIFETIME)
        return sorted(
            [{"priority": r.preference, "host": str(r.exchange).rstrip(".")} for r in answers],
            key=lambda x: x["priority"],
        )
    except Exception:
        return []


def _query_soa(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "SOA", lifetime=_LIFETIME)
        r = answers[0]
        return {
            "mname":   str(r.mname).rstrip("."),
            "rname":   str(r.rname).rstrip(".").replace(".", "@", 1),
            "serial":  r.serial,
            "refresh": r.refresh,
            "retry":   r.retry,
            "expire":  r.expire,
            "minimum": r.minimum,
        }
    except Exception:
        return {}


def _query_caa(domain: str) -> list[dict]:
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=_LIFETIME)
        return [{"flag": r.flags, "tag": r.tag.decode(), "value": r.value.decode()} for r in answers]
    except Exception:
        return []


def _ptr(ip: str) -> str:
    try:
        rev = dns.resolver.resolve(dns.reversename.from_address(ip), "PTR", lifetime=_LIFETIME)
        return str(rev[0]).rstrip(".")
    except Exception:
        return ip   # return raw IP on failure


# ─────────────────────────────────────────────
# SPF parsing
# ─────────────────────────────────────────────

def _parse_spf(txt_records: list[str]) -> dict:
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            parts = record.split()
            mechanisms = [p for p in parts[1:] if not p.startswith("~all")
                          and not p.startswith("-all") and not p.startswith("+all") and not p.startswith("?all")]
            all_policy = "none"
            for p in parts:
                if p in ("-all", "~all", "+all", "?all"):
                    all_policy = {"- all": "fail", "-all": "fail",
                                  "~all": "softfail", "+all": "pass", "?all": "neutral"}.get(p, p)
            return {
                "raw":        record,
                "mechanisms": mechanisms,
                "all_policy": all_policy,
                "strict":     all_policy == "fail",
            }
    return {"raw": "", "mechanisms": [], "all_policy": "none", "strict": False}


# ─────────────────────────────────────────────
# DMARC
# ─────────────────────────────────────────────

def _query_dmarc(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=_LIFETIME)
        for r in answers:
            raw = b"".join(r.strings).decode("utf-8", errors="replace")
            if "v=DMARC1" in raw:
                tags = dict(
                    item.strip().split("=", 1)
                    for item in raw.split(";")
                    if "=" in item
                )
                return {
                    "raw":    raw,
                    "policy": tags.get("p", "none"),
                    "sp":     tags.get("sp", "none"),    # subdomain policy
                    "pct":    tags.get("pct", "100"),    # % of mail
                    "rua":    tags.get("rua", ""),       # aggregate reports
                    "ruf":    tags.get("ruf", ""),       # forensic reports
                    "adkim":  tags.get("adkim", "r"),    # DKIM alignment
                    "aspf":   tags.get("aspf", "r"),     # SPF alignment
                }
    except Exception:
        pass
    return {"raw": "", "policy": "none"}


# ─────────────────────────────────────────────
# DKIM selector probes
# ─────────────────────────────────────────────

_DKIM_SELECTORS = [
    "default", "google", "k1", "k2", "s1", "s2",
    "mail", "email", "dkim", "selector1", "selector2",
    "mimecast", "proofpoint", "pm", "mandrill", "sendgrid",
    "smtp", "key1", "key2", "x", "mx",
]

def _probe_dkim(domain: str) -> list[str]:
    found = []
    for sel in _DKIM_SELECTORS:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=3)
            found.append(sel)
        except Exception:
            pass
    return found


# ─────────────────────────────────────────────
# DNSSEC & wildcard
# ─────────────────────────────────────────────

def _check_dnssec(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=_LIFETIME)
        return True
    except Exception:
        return False


def _check_wildcard(domain: str) -> bool:
    try:
        dns.resolver.resolve(f"this-host-should-not-exist-xyz123.{domain}", "A", lifetime=4)
        return True   # resolved → wildcard DNS
    except Exception:
        return False


# ─────────────────────────────────────────────
# Zone transfer (AXFR)
# ─────────────────────────────────────────────

def _zone_transfer(domain: str, nameservers: list[str]) -> list[str]:
    records: list[str] = []
    for ns in nameservers[:3]:     # try first 3 NS only
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            for name, node in z.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name}.{domain} {rdataset.rdtype} {rdata}")
            if records:
                break
        except Exception:
            pass
    return records


# ─────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────

def _clean(domain: str) -> str:
    return domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]