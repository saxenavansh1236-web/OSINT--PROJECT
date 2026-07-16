"""
otx_lookup.py
Queries AlienVault OTX (Open Threat Exchange) for threat intelligence.
Returns pulse count, malware families, threat types, and IOCs.
Free API key from: https://otx.alienvault.com/api
Set env var: OTX_API_KEY=your_key
"""

import os
import re
import requests
from dataclasses import dataclass, field
from typing import Optional

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_BASE    = "https://otx.alienvault.com/api/v1"


@dataclass
class OTXResult:
    target:          str  = ""
    target_type:     str  = ""           # domain / ip / url / hostname
    pulse_count:     int  = 0            # number of threat pulses
    flagged:         bool = False
    threat_score:    int  = 0            # 0-100 derived score

    # Threat intel
    malware_families: list = field(default_factory=list)
    adversaries:      list = field(default_factory=list)
    threat_types:     list = field(default_factory=list)
    tags:             list = field(default_factory=list)

    # Pulses (threat reports)
    pulses:          list = field(default_factory=list)  # list of {name, description, author, created, tags}

    # IOCs (Indicators of Compromise)
    iocs:            list = field(default_factory=list)  # {indicator, type, description}

    # Geo / network
    country:         str  = ""
    asn:             str  = ""
    city:            str  = ""

    # Domain specific
    whois_info:      dict = field(default_factory=dict)
    dns_records:     list = field(default_factory=list)
    subdomains:      list = field(default_factory=list)
    url_list:        list = field(default_factory=list)

    # IP specific
    reputation:      int  = 0

    link:            str  = ""
    error:           Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _detect_type(target: str) -> str:
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, target):
        return "ip"
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    return "domain"


def _headers() -> dict:
    return {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}


def _calc_threat_score(pulse_count: int, malware_count: int) -> int:
    score = min(pulse_count * 8, 60) + min(malware_count * 15, 40)
    return min(score, 100)


def _parse_pulses(general_data: dict, result: OTXResult):
    pulse_info = general_data.get("pulse_info", {})
    result.pulse_count = pulse_info.get("count", 0)

    pulses_raw = pulse_info.get("pulses", [])[:10]
    result.pulses = [
        {
            "name":        p.get("name",        ""),
            "description": (p.get("description", "") or "")[:300],
            "author":      p.get("author_name", ""),
            "created":     p.get("created",     ""),
            "tags":        p.get("tags",         [])[:5],
            "malware_families": p.get("malware_families", []),
            "adversary":   p.get("adversary",   ""),
            "tlp":         p.get("tlp",         "white"),
        }
        for p in pulses_raw
    ]

    # Aggregate malware families & tags
    malware = set()
    tags    = set()
    adv     = set()
    for p in pulses_raw:
        for m in p.get("malware_families", []):
            malware.add(m)
        for t in p.get("tags", []):
            tags.add(t)
        if p.get("adversary"):
            adv.add(p["adversary"])

    result.malware_families = list(malware)[:10]
    result.tags             = list(tags)[:15]
    result.adversaries      = list(adv)[:5]
    result.threat_score     = _calc_threat_score(result.pulse_count, len(malware))
    result.flagged          = result.pulse_count > 0


def _fetch_section(target_type: str, target: str, section: str) -> dict:
    try:
        resp = requests.get(
            f"{OTX_BASE}/indicators/{target_type}/{target}/{section}",
            headers=_headers(),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


def lookup_domain(target: str) -> OTXResult:
    result = OTXResult(target=target, target_type="domain")
    result.link = f"https://otx.alienvault.com/indicator/domain/{target}"

    if not OTX_API_KEY:
        result.error = "OTX_API_KEY not set"
        return result

    try:
        # General / pulse info
        general = _fetch_section("domain", target, "general")
        _parse_pulses(general, result)

        # DNS records
        geo = _fetch_section("domain", target, "geo")
        result.country = geo.get("country_name", "")
        result.city    = geo.get("city",         "")
        result.asn     = geo.get("asn",          "")

        # DNS
        dns_data = _fetch_section("domain", target, "passive_dns")
        result.dns_records = [
            {
                "hostname":   d.get("hostname", ""),
                "address":    d.get("address",  ""),
                "record_type":d.get("record_type",""),
                "first":      d.get("first",    ""),
                "last":       d.get("last",     ""),
            }
            for d in dns_data.get("passive_dns", [])[:10]
        ]

        # Subdomains
        sub_data = _fetch_section("domain", target, "http_scans")
        result.url_list = [
            u.get("url", "")
            for u in sub_data.get("url_list", [])[:10]
        ]

        # Malware IOCs
        mal_data = _fetch_section("domain", target, "malware")
        result.iocs = [
            {
                "hash":    m.get("hash",    ""),
                "detections": m.get("detections", {}).get("count", 0),
            }
            for m in mal_data.get("data", [])[:10]
        ]

    except Exception as e:
        result.error = str(e)

    return result


def lookup_ip(target: str) -> OTXResult:
    result = OTXResult(target=target, target_type="ip")
    result.link = f"https://otx.alienvault.com/indicator/ip/{target}"

    if not OTX_API_KEY:
        result.error = "OTX_API_KEY not set"
        return result

    try:
        general = _fetch_section("IPv4", target, "general")
        _parse_pulses(general, result)
        result.reputation = general.get("reputation", 0)

        geo = _fetch_section("IPv4", target, "geo")
        result.country = geo.get("country_name", "")
        result.city    = geo.get("city",         "")
        result.asn     = geo.get("asn",          "")

        # Passive DNS
        dns_data = _fetch_section("IPv4", target, "passive_dns")
        result.dns_records = [
            {
                "hostname":   d.get("hostname", ""),
                "record_type":d.get("record_type",""),
                "first":      d.get("first",    ""),
                "last":       d.get("last",     ""),
            }
            for d in dns_data.get("passive_dns", [])[:10]
        ]

        # Malware
        mal_data = _fetch_section("IPv4", target, "malware")
        result.iocs = [
            {"hash": m.get("hash", ""), "detections": m.get("detections", {}).get("count", 0)}
            for m in mal_data.get("data", [])[:10]
        ]

    except Exception as e:
        result.error = str(e)

    return result


def lookup_url(target: str) -> OTXResult:
    result = OTXResult(target=target, target_type="url")
    result.link = f"https://otx.alienvault.com/indicator/url/{target}"

    if not OTX_API_KEY:
        result.error = "OTX_API_KEY not set"
        return result

    try:
        general = _fetch_section("url", target, "general")
        _parse_pulses(general, result)
    except Exception as e:
        result.error = str(e)

    return result


def lookup(target: str) -> OTXResult:
    """Auto-detect target type and run the appropriate OTX lookup."""
    t = _detect_type(target)
    if t == "ip":
        return lookup_ip(target)
    if t == "url":
        return lookup_url(target)
    return lookup_domain(target)