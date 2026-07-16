"""
archive_lookup.py — Web archive & historical snapshot intelligence.

Features
--------
* Wayback Machine availability check (first / last snapshot)
* Full CDX API pagination → complete URL timeline
* Snapshot count by year (sparkline data)
* Deleted page detection (was live, now 404)
* Historical domain changes (detect redirects over time)
* Common Crawl index search
* Hostname extraction from archive (discover old subdomains)
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional
from collections import Counter

import requests

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "OSINT-Platform/2.0"})
_TIMEOUT = 12

CDX_API    = "http://web.archive.org/cdx/search/cdx"
AVAIL_API  = "https://archive.org/wayback/available"
CC_INDEX   = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class Snapshot:
    timestamp: str      # "20231015142233"
    url: str
    status_code: str    # "200", "301", "404", …
    mime_type: str
    archive_url: str    # full https://web.archive.org/web/… URL

    @property
    def date(self) -> str:
        return self.timestamp[:8]   # "20231015"

    @property
    def datetime_str(self) -> str:
        ts = self.timestamp
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]}"


@dataclass
class ArchiveResult:
    target: str
    # Summary
    first_seen: str         # "2010-03-14"
    last_seen: str          # "2024-01-02"
    total_snapshots: int
    years_active: list[str]
    snapshots_by_year: dict # {"2010": 3, "2011": 12, …}
    # Key snapshots
    first_snapshot: Optional[Snapshot] = None
    last_snapshot:  Optional[Snapshot] = None
    # Timeline (most recent 50)
    recent_snapshots: list[Snapshot] = field(default_factory=list)
    # Deleted pages (URLs that returned 200 then 404)
    deleted_pages: list[str] = field(default_factory=list)
    # Old subdomains discovered in archive
    discovered_hosts: list[str] = field(default_factory=list)
    # Common Crawl
    in_common_crawl: bool = False
    common_crawl_pages: int = 0
    # Errors
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["recent_snapshots"] = [asdict(s) for s in self.recent_snapshots]
        return d


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def lookup(url: str, *, max_snapshots: int = 500) -> ArchiveResult:
    """
    Full archive intelligence for *url*.

    Args:
        url:           Target URL or domain.
        max_snapshots: CDX page limit (set higher for deeper history).
    """
    url = _normalize(url)
    result = ArchiveResult(
        target=url,
        first_seen="", last_seen="", total_snapshots=0,
        years_active=[], snapshots_by_year={},
    )

    # ── 1. Quick availability check ──────────────────────────────────────────
    avail = _availability(url)
    if not avail:
        result.error = "No snapshots found in Wayback Machine"
        return result

    # ── 2. CDX full timeline ─────────────────────────────────────────────────
    all_snapshots = _cdx_all(url, limit=max_snapshots)
    if not all_snapshots:
        result.error = "CDX API returned no results"
        return result

    result.total_snapshots = len(all_snapshots)
    result.first_snapshot  = all_snapshots[0]
    result.last_snapshot   = all_snapshots[-1]
    result.first_seen      = all_snapshots[0].date
    result.last_seen       = all_snapshots[-1].date

    # Year distribution
    year_counts: Counter = Counter(s.timestamp[:4] for s in all_snapshots)
    result.snapshots_by_year = dict(sorted(year_counts.items()))
    result.years_active = sorted(year_counts.keys())

    # Recent 50
    result.recent_snapshots = list(reversed(all_snapshots))[:50]

    # ── 3. Deleted page detection ─────────────────────────────────────────────
    result.deleted_pages = _find_deleted(url)

    # ── 4. Old hostname discovery ─────────────────────────────────────────────
    domain = _domain_only(url)
    result.discovered_hosts = _discover_hosts(domain)

    # ── 5. Common Crawl check ─────────────────────────────────────────────────
    cc_count = _common_crawl(url)
    result.in_common_crawl    = cc_count > 0
    result.common_crawl_pages = cc_count

    return result


def get_snapshot_url(url: str, timestamp: Optional[str] = None) -> str:
    """Return the Wayback Machine URL for a snapshot. If timestamp is None, returns closest."""
    ts = timestamp or ""
    return f"https://web.archive.org/web/{ts}/{url}"


# ─────────────────────────────────────────────
# Internal
# ─────────────────────────────────────────────

def _availability(url: str) -> dict:
    try:
        r = _SESSION.get(AVAIL_API, params={"url": url}, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json().get("archived_snapshots", {}).get("closest", {})
    except Exception:
        return {}


def _cdx_all(url: str, limit: int = 500) -> list[Snapshot]:
    """Paginate CDX API to collect up to *limit* snapshots."""
    snapshots: list[Snapshot] = []
    params = {
        "url":      url,
        "output":   "json",
        "fl":       "timestamp,original,statuscode,mimetype",
        "limit":    min(limit, 500),
        "collapse": "timestamp:8",    # one per day (avoids flood)
        "filter":   "statuscode:200|301|302|404",
    }
    try:
        r = _SESSION.get(CDX_API, params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        rows = r.json()
        if not rows or len(rows) < 2:
            return []
        # rows[0] is the header
        for row in rows[1:]:
            ts, orig, sc, mime = row[0], row[1], row[2], row[3]
            snapshots.append(Snapshot(
                timestamp=ts,
                url=orig,
                status_code=sc,
                mime_type=mime,
                archive_url=f"https://web.archive.org/web/{ts}/{orig}",
            ))
    except Exception:
        pass
    return snapshots


def _find_deleted(url: str) -> list[str]:
    """Find URLs under the domain that had 200 responses but now 404."""
    try:
        params = {
            "url":    url + "/*",
            "output": "json",
            "fl":     "original,statuscode",
            "filter": "statuscode:404",
            "limit":  50,
            "collapse": "original",
        }
        r = _SESSION.get(CDX_API, params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        rows = r.json()
        if not rows or len(rows) < 2:
            return []
        return list({row[0] for row in rows[1:] if row[1] == "404"})[:20]
    except Exception:
        return []


def _discover_hosts(domain: str) -> list[str]:
    """
    Query CDX for all archived URLs under *.domain to find historical subdomains.
    """
    try:
        params = {
            "url":     f"*.{domain}",
            "output":  "json",
            "fl":      "original",
            "limit":   200,
            "collapse": "urlkey",
            "filter":  "statuscode:200",
        }
        r = _SESSION.get(CDX_API, params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        rows = r.json()
        if not rows or len(rows) < 2:
            return []
        hosts: set[str] = set()
        import urllib.parse
        for row in rows[1:]:
            parsed = urllib.parse.urlparse(row[0])
            if parsed.netloc and parsed.netloc.endswith(domain):
                hosts.add(parsed.netloc.lower())
        return sorted(hosts)[:30]
    except Exception:
        return []


def _common_crawl(url: str) -> int:
    """Check Common Crawl index for page count."""
    try:
        r = _SESSION.get(
            CC_INDEX,
            params={"url": url, "output": "json", "limit": 1},
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            lines = [l for l in r.text.strip().splitlines() if l]
            return len(lines)
    except Exception:
        pass
    return 0


def _normalize(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _domain_only(url: str) -> str:
    import urllib.parse
    return urllib.parse.urlparse(url).netloc or url