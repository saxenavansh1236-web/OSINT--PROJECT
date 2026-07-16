"""
virustotal.py
Checks domains, IPs, and URLs against the VirusTotal API.
Requires a free API key from https://www.virustotal.com
Set env var: VIRUSTOTAL_API_KEY=your_key
"""

import os
import re
import time
import requests
from dataclasses import dataclass, field
from typing import Optional

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE    = "https://www.virustotal.com/api/v3"
HEADERS    = {"x-apikey": VT_API_KEY, "Accept": "application/json"}


@dataclass
class VTResult:
    target:          str  = ""
    target_type:     str  = ""
    malicious:       int  = 0
    suspicious:      int  = 0
    harmless:        int  = 0
    undetected:      int  = 0
    total_engines:   int  = 0
    reputation:      int  = 0
    threat_names:    list = field(default_factory=list)
    categories:      dict = field(default_factory=dict)
    last_analysis:   str  = ""
    country:         str  = ""
    as_owner:        str  = ""
    link:            str  = ""
    flagged:         bool = False
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


def _get_headers() -> dict:
    """Build headers fresh so they pick up the env var at call time."""
    return {"x-apikey": os.environ.get("VIRUSTOTAL_API_KEY", VT_API_KEY), "Accept": "application/json"}


def _parse_stats(data: dict, result: VTResult):
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    result.malicious     = stats.get("malicious",  0)
    result.suspicious    = stats.get("suspicious", 0)
    result.harmless      = stats.get("harmless",   0)
    result.undetected    = stats.get("undetected", 0)
    result.total_engines = sum(stats.values())
    result.reputation    = attrs.get("reputation", 0)
    result.flagged       = result.malicious > 0 or result.suspicious > 0

    analysis = attrs.get("last_analysis_results", {})
    names = set()
    for engine in analysis.values():
        name = engine.get("result")
        if name and engine.get("category") in ("malicious", "suspicious"):
            names.add(name)
    result.threat_names = list(names)[:10]
    result.categories   = attrs.get("categories", {})

    ts = attrs.get("last_analysis_date")
    if ts:
        result.last_analysis = time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))


def scan_domain(target: str) -> VTResult:
    result = VTResult(target=target, target_type="domain")
    result.link = f"https://www.virustotal.com/gui/domain/{target}"
    if not VT_API_KEY:
        result.error = "VIRUSTOTAL_API_KEY not set"
        return result
    try:
        resp = requests.get(f"{VT_BASE}/domains/{target}", headers=_get_headers(), timeout=15)
        if resp.status_code == 404:
            result.error = "Domain not found in VirusTotal"
            return result
        resp.raise_for_status()
        data = resp.json().get("data", {})
        _parse_stats(data, result)
    except Exception as e:
        result.error = str(e)
    return result


def scan_ip(target: str) -> VTResult:
    result = VTResult(target=target, target_type="ip")
    result.link = f"https://www.virustotal.com/gui/ip-address/{target}"
    if not VT_API_KEY:
        result.error = "VIRUSTOTAL_API_KEY not set"
        return result
    try:
        resp = requests.get(f"{VT_BASE}/ip_addresses/{target}", headers=_get_headers(), timeout=15)
        resp.raise_for_status()
        data  = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        result.country  = attrs.get("country",  "")
        result.as_owner = attrs.get("as_owner", "")
        _parse_stats(data, result)
    except Exception as e:
        result.error = str(e)
    return result


def scan_url(target: str) -> VTResult:
    result = VTResult(target=target, target_type="url")
    if not VT_API_KEY:
        result.error = "VIRUSTOTAL_API_KEY not set"
        return result
    try:
        resp = requests.post(
            f"{VT_BASE}/urls",
            headers=_get_headers(),
            data={"url": target},
            timeout=15,
        )
        resp.raise_for_status()
        analysis_id = resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            result.error = "No analysis ID returned"
            return result

        for _ in range(3):
            time.sleep(3)
            poll = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=_get_headers(),
                timeout=15,
            )
            poll.raise_for_status()
            poll_data = poll.json().get("data", {})
            status = poll_data.get("attributes", {}).get("status")
            if status == "completed":
                _parse_stats(poll_data, result)
                break
        else:
            result.error = "Analysis timed out"

        result.link = f"https://www.virustotal.com/gui/url/{analysis_id}"
    except Exception as e:
        result.error = str(e)
    return result


def lookup(target: str) -> VTResult:
    """Auto-detect target type and run the appropriate scan."""
    t = _detect_type(target)
    if t == "ip":
        return scan_ip(target)
    if t == "url":
        return scan_url(target)
    return scan_domain(target)