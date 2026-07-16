"""
paste_monitor.py
Monitor public paste sites for mentions of a target (domain, email, username, IP).

Sources
-------
  psbdmp      — public Pastebin dump search API
  github_gist — GitHub public Gist feed
  grep.app    — code search across public GitHub repos
  IntelX      — delegated to leak_checker._intelx() (no duplicate logic)

The IntelX paste search is deliberately NOT reimplemented here.
leak_checker._intelx() is the single source of truth; paste_monitor
converts its LeakEntry objects to PasteMention objects when needed.
"""

from __future__ import annotations

import os
import time
import requests
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import List

# Reuse IntelX logic from leak_checker — no duplicate implementation
from leak_checker import _intelx as _intelx_search, INTELX_KEY

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

SEVERITY_MAP = {
    "password":    "critical",
    "passwd":      "critical",
    "secret":      "critical",
    "api_key":     "critical",
    "apikey":      "critical",
    "private_key": "critical",
    "db_pass":     "critical",
    "token":       "high",
    "credential":  "high",
    "ssh":         "high",
    "database":    "high",
    "leak":        "high",
    "breach":      "high",
    "exploit":     "high",
    "dump":        "medium",
    "hack":        "medium",
    "vulnerability": "medium",
    "email":       "low",
    "phone":       "low",
    "address":     "low",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class PasteMention:
    source:              str
    paste_url:           str
    paste_id:            str
    title:               str
    date:                str
    snippet:             str
    severity:            str
    keywords_found:      List[str] = field(default_factory=list)
    raw_content_preview: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PasteMonitorResult:
    target:         str
    total_found:    int = 0
    mentions:       List[PasteMention] = field(default_factory=list)
    critical_count: int = 0
    high_count:     int = 0
    medium_count:   int = 0
    low_count:      int = 0
    sources_checked: List[str] = field(default_factory=list)
    scanned_at:     str = ""
    summary:        str = ""

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "total_found":    self.total_found,
            "critical_count": self.critical_count,
            "high_count":     self.high_count,
            "medium_count":   self.medium_count,
            "low_count":      self.low_count,
            "mentions":       [m.to_dict() for m in self.mentions],
            "sources_checked": self.sources_checked,
            "scanned_at":     self.scanned_at,
            "summary":        self.summary,
        }


# ─────────────────────────────────────────────
# Severity assessment
# ─────────────────────────────────────────────

def _assess_severity(text: str) -> tuple[str, List[str]]:
    """Return (severity, keywords_found) based on content keywords."""
    text_lower = text.lower()
    found: List[str] = []
    highest = "low"
    priority = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for kw, sev in SEVERITY_MAP.items():
        if kw in text_lower:
            found.append(kw)
            if priority.get(sev, 0) > priority.get(highest, 0):
                highest = sev
    return highest, found


# ─────────────────────────────────────────────
# Source: psbdmp
# ─────────────────────────────────────────────

def _search_psbdmp(query: str, timeout: int = 8) -> List[PasteMention]:
    mentions: List[PasteMention] = []
    try:
        url  = f"https://psbdmp.ws/api/search/{requests.utils.quote(query)}"
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        if resp.status_code != 200:
            return mentions

        data   = resp.json()
        pastes = data if isinstance(data, list) else data.get("data", [])

        for item in pastes[:20]:
            paste_id = item.get("id", "")
            content  = item.get("text", "") or item.get("content", "")
            title    = item.get("title", "Untitled")
            date     = item.get("time", "") or item.get("date", "")
            severity, keywords = _assess_severity(content or title)

            mentions.append(PasteMention(
                source="psbdmp",
                paste_url=f"https://pastebin.com/{paste_id}",
                paste_id=paste_id,
                title=title or "Untitled",
                date=str(date),
                snippet=content[:300],
                severity=severity,
                keywords_found=keywords,
                raw_content_preview=content[:500],
            ))
    except Exception as e:
        print(f"[paste_monitor/psbdmp] {e}")
    return mentions


# ─────────────────────────────────────────────
# Source: GitHub Gist
# ─────────────────────────────────────────────

def _search_github_gist(query: str, timeout: int = 8) -> List[PasteMention]:
    mentions: List[PasteMention] = []
    try:
        resp = requests.get(
            "https://api.github.com/gists/public",
            headers=HEADERS,
            params={"per_page": 30},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return mentions

        query_lower = query.lower()
        for gist in resp.json():
            description = (gist.get("description") or "").lower()
            files       = gist.get("files", {})
            filenames   = " ".join(files.keys()).lower()
            combined    = description + " " + filenames

            if query_lower not in combined:
                continue

            severity, keywords = _assess_severity(combined)
            mentions.append(PasteMention(
                source="github_gist",
                paste_url=gist.get("html_url", ""),
                paste_id=gist.get("id", ""),
                title=gist.get("description") or "GitHub Gist",
                date=(gist.get("created_at", "") or "")[:10],
                snippet=f"Files: {', '.join(list(files.keys())[:5])}",
                severity=severity,
                keywords_found=keywords,
            ))
    except Exception as e:
        print(f"[paste_monitor/github_gist] {e}")
    return mentions


# ─────────────────────────────────────────────
# Source: grep.app
# ─────────────────────────────────────────────

def _search_grep_app(query: str, timeout: int = 8) -> List[PasteMention]:
    mentions: List[PasteMention] = []
    try:
        resp = requests.get(
            "https://grep.app/api/search",
            headers=HEADERS,
            params={"q": query, "limit": 10},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return mentions

        for hit in resp.json().get("hits", {}).get("hits", [])[:10]:
            src       = hit.get("_source", {})
            repo      = src.get("repo", {})
            content   = hit.get("content", {}).get("snippet", "")
            filepath  = src.get("path", "")
            repo_name = repo.get("name", "")
            severity, keywords = _assess_severity(content)

            mentions.append(PasteMention(
                source="grep.app (GitHub)",
                paste_url=f"https://github.com/{repo_name}",
                paste_id=repo_name.replace("/", "_"),
                title=f"{repo_name}: {filepath}",
                date="",
                snippet=content[:300],
                severity=severity,
                keywords_found=keywords,
            ))
    except Exception as e:
        print(f"[paste_monitor/grep_app] {e}")
    return mentions


# ─────────────────────────────────────────────
# Source: IntelX  (via leak_checker — no duplicate)
# ─────────────────────────────────────────────

def _search_intelx(target: str) -> List[PasteMention]:
    """
    Converts LeakEntry objects from leak_checker._intelx() into PasteMention
    objects.  This is the ONLY place IntelX is called for paste monitoring —
    all credential/parameter handling lives in leak_checker.
    """
    if not INTELX_KEY:
        return []

    # Detect target type for leak_checker
    ttype = "email" if "@" in target else "domain"
    entries = _intelx_search(target, ttype)

    return [
        PasteMention(
            source="IntelX",
            paste_url="https://intelx.io/",
            paste_id=e.breach_name.replace(" ", "_")[:40],
            title=e.breach_name,
            date=e.date,
            snippet=e.description,
            severity=e.severity,
            keywords_found=[],
        )
        for e in entries
    ]


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def monitor(target: str, timeout: int = 8) -> PasteMonitorResult:
    """
    Monitor public paste sites and code repos for mentions of *target*.

    Args:
        target:  Domain, email, username, or IP to search for.
        timeout: Per-source request timeout in seconds.

    Returns:
        PasteMonitorResult dataclass with all findings.
    """
    result = PasteMonitorResult(
        target=target,
        scanned_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    all_mentions: List[PasteMention] = []

    # psbdmp
    result.sources_checked.append("psbdmp")
    all_mentions.extend(_search_psbdmp(target, timeout))
    time.sleep(0.5)

    # GitHub Gist
    result.sources_checked.append("github_gist")
    all_mentions.extend(_search_github_gist(target, timeout))
    time.sleep(0.3)

    # grep.app
    result.sources_checked.append("grep.app")
    all_mentions.extend(_search_grep_app(target, timeout))

    # IntelX (via leak_checker — no duplicated API logic)
    if INTELX_KEY:
        result.sources_checked.append("IntelX (via leak_checker)")
        all_mentions.extend(_search_intelx(target))

    # Deduplicate by paste_id
    seen: set[str] = set()
    unique: List[PasteMention] = []
    for m in all_mentions:
        if m.paste_id not in seen:
            seen.add(m.paste_id)
            unique.append(m)

    # Sort by severity
    unique.sort(key=lambda x: _SEV_ORDER.get(x.severity, 4))

    result.mentions       = unique
    result.total_found    = len(unique)
    result.critical_count = sum(1 for m in unique if m.severity == "critical")
    result.high_count     = sum(1 for m in unique if m.severity == "high")
    result.medium_count   = sum(1 for m in unique if m.severity == "medium")
    result.low_count      = sum(1 for m in unique if m.severity == "low")

    if result.total_found == 0:
        result.summary = (
            f"No paste mentions found for '{target}' "
            f"across {len(result.sources_checked)} sources."
        )
    else:
        result.summary = (
            f"Found {result.total_found} paste mentions for '{target}'. "
            f"Critical: {result.critical_count}, High: {result.high_count}, "
            f"Medium: {result.medium_count}, Low: {result.low_count}."
        )

    return result