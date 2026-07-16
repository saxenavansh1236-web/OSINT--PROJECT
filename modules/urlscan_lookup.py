"""
urlscan_lookup.py
Submits URLs/domains to urlscan.io for analysis.
Returns screenshot URL, page info, verdicts, links, and certificates.
Free tier: 100 scans/day. No key needed for public scans.
Optional API key for faster results: https://urlscan.io/user/signup
Set env var: URLSCAN_API_KEY=your_key
"""

import os
import re
import time
import requests
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "").strip()
URLSCAN_BASE    = "https://urlscan.io/api/v1"

# urlscan.io API keys are UUIDs, e.g. 0198f129-08da-7078-9a8d-8f35499d9693
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass
class URLScanResult:
    target:           str  = ""
    scan_id:          str  = ""
    scan_url:         str  = ""
    screenshot_url:   str  = ""
    dom_url:          str  = ""

    page_url:         str  = ""
    page_title:       str  = ""
    page_ip:          str  = ""
    page_country:     str  = ""
    page_server:      str  = ""
    page_mime:        str  = ""
    page_status:      int  = 0

    overall_verdict:  str  = "unknown"
    malicious:        bool = False
    score:            int  = 0

    links:            list = field(default_factory=list)
    ips:              list = field(default_factory=list)
    domains:          list = field(default_factory=list)
    certificates:     list = field(default_factory=list)
    technologies:     list = field(default_factory=list)
    asns:             list = field(default_factory=list)

    submitted_at:     str  = ""
    error:            Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _build_url(target: str) -> str:
    """
    Normalize arbitrary input (bare domain, URL with scheme, URL with
    stray whitespace or trailing slash weirdness) into a clean, single
    https://... URL that urlscan.io's API will accept.
    """
    target = (target or "").strip()

    # Collapse an accidentally-doubled scheme, e.g. "https://https://x.com"
    target = re.sub(r"^(https?://)+", "", target, flags=re.IGNORECASE)

    if not target:
        return target

    url = f"https://{target}"

    # Validate it actually parses into something with a real hostname
    parsed = urlparse(url)
    if not parsed.hostname:
        return ""

    return url


def _validate_api_key(key: str) -> bool:
    return bool(key) and bool(_UUID_RE.match(key))


def lookup(target: str, wait_secs: int = 15) -> URLScanResult:
    result = URLScanResult(target=target)
    url    = _build_url(target)

    if not url:
        result.error = f"Could not parse '{target}' into a valid URL"
        return result

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "phishing-url-detector/1.0 (+https://github.com/)",
    }
    if URLSCAN_API_KEY:
        if not _validate_api_key(URLSCAN_API_KEY):
            result.error = (
                "URLSCAN_API_KEY is set but not a valid urlscan.io key format "
                "(expected a UUID like 0198f129-08da-7078-9a8d-8f35499d9693). "
                "Double-check you copied it correctly with no extra characters."
            )
            return result
        headers["API-Key"] = URLSCAN_API_KEY

    # ── Submit scan ───────────────────────────────────────────────────────────
    try:
        resp = requests.post(
            f"{URLSCAN_BASE}/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=15,
        )
        if resp.status_code == 401:
            result.error = "Invalid or unauthorized URLSCAN_API_KEY"
            return result
        if resp.status_code == 429:
            result.error = "Rate limit reached — try again later"
            return result
        if resp.status_code == 400:
            try:
                detail = resp.json().get("message", "")
            except Exception:
                detail = resp.text[:200]
            result.error = f"Invalid URL submitted: {detail or url}"
            return result
        resp.raise_for_status()

        data            = resp.json()
        result.scan_id  = data.get("uuid", "")
        result.scan_url = data.get("result", "")
        result.submitted_at = data.get("api", "")

        if not result.scan_id:
            result.error = "No scan ID returned"
            return result

    except Exception as e:
        result.error = f"Submit failed: {e}"
        return result

    # ── Wait for scan to complete ─────────────────────────────────────────────
    time.sleep(wait_secs)

    # ── Fetch results ─────────────────────────────────────────────────────────
    result_headers = {
        # urlscan.io's edge (Cloudflare) will 403 requests with no/blank
        # User-Agent — always identify the client explicitly.
        "User-Agent": "phishing-url-detector/1.0 (+https://github.com/)",
    }
    if URLSCAN_API_KEY and _validate_api_key(URLSCAN_API_KEY):
        result_headers["API-Key"] = URLSCAN_API_KEY

    try:
        for attempt in range(4):
            res = requests.get(
                f"{URLSCAN_BASE}/result/{result.scan_id}/",
                headers=result_headers,
                timeout=20,
            )
            if res.status_code == 404:
                time.sleep(5)
                continue
            if res.status_code == 403:
                # Scan is often still processing/indexing — back off and retry
                # rather than failing immediately on the first 403.
                time.sleep(5)
                continue
            res.raise_for_status()
            scan_data = res.json()
            break
        else:
            result.error = (
                "Scan results not ready or access forbidden — "
                f"view manually: {result.scan_url or 'https://urlscan.io/result/' + result.scan_id + '/'}"
            )
            result.screenshot_url = f"https://urlscan.io/screenshots/{result.scan_id}.png"
            return result

        page = scan_data.get("page", {})
        result.page_url     = page.get("url",      "")
        result.page_title   = page.get("title",    "")
        result.page_ip      = page.get("ip",       "")
        result.page_country = page.get("country",  "")
        result.page_server  = page.get("server",   "")
        result.page_mime    = page.get("mimeType", "")
        result.page_status  = page.get("status",   0)

        result.screenshot_url = f"https://urlscan.io/screenshots/{result.scan_id}.png"
        result.dom_url        = f"https://urlscan.io/dom/{result.scan_id}/"

        verdicts = scan_data.get("verdicts", {})
        overall  = verdicts.get("overall", {})
        result.overall_verdict = overall.get("verdict", "unknown") or "unknown"
        result.malicious       = overall.get("malicious", False)
        result.score           = overall.get("score", 0)

        lists = scan_data.get("lists", {})
        result.ips      = lists.get("ips",     [])[:20]
        result.domains  = lists.get("domains", [])[:20]
        result.links    = lists.get("urls",    [])[:20]
        result.asns     = lists.get("asns",    [])[:10]

        certs = lists.get("certificates", [])
        result.certificates = [
            {
                "subject":    c.get("subjectName", ""),
                "issuer":     c.get("issuer",      ""),
                "valid_from": c.get("validFrom",   ""),
                "valid_to":   c.get("validTo",     ""),
            }
            for c in certs[:5]
        ]

        tech  = scan_data.get("meta", {}).get("processors", {})
        wappa = tech.get("wappa", {}).get("data", [])
        result.technologies = [t.get("app", "") for t in wappa if t.get("app")][:15]

    except Exception as e:
        result.error = f"Result fetch failed: {e}"
        result.screenshot_url = f"https://urlscan.io/screenshots/{result.scan_id}.png"

    return result