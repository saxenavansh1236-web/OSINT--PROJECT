"""
robots_scan.py — Discover hidden paths via robots.txt, sitemap.xml, and common files
"""

import urllib.request
import urllib.error
import ssl
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Optional


# Paths that are interesting from a security perspective
SENSITIVE_PATH_PATTERNS = [
    r"admin", r"login", r"panel", r"dashboard", r"config", r"backup",
    r"\.env", r"database", r"db", r"api", r"swagger", r"phpmyadmin",
    r"wp-admin", r"\.git", r"\.svn", r"secret", r"private", r"internal",
    r"upload", r"install", r"setup", r"\.sql", r"\.bak", r"debug",
    r"test", r"dev", r"staging", r"console",
]

# Common files to probe
COMMON_FILES = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/security.txt",
    "/.git/config", "/.env", "/crossdomain.xml",
    "/humans.txt", "/ads.txt", "/app-ads.txt",
]


@dataclass
class DiscoveredPath:
    path: str
    source: str         # robots.txt / sitemap / common-file
    status_code: int = 0
    sensitive: bool = False
    reason: str = ""


@dataclass
class RobotsScan:
    target: str
    robots_txt: str = ""
    disallowed_paths: list = field(default_factory=list)
    allowed_paths: list = field(default_factory=list)
    sitemap_urls: list = field(default_factory=list)
    discovered_paths: list = field(default_factory=list)   # DiscoveredPath dicts
    sensitive_paths: list = field(default_factory=list)
    security_txt: str = ""
    files_found: list = field(default_factory=list)
    total_paths: int = 0
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def _get(url: str, timeout: int = 8) -> tuple:
    """Returns (text_content, status_code)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (Security-Research/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="replace"), r.status
    except urllib.error.HTTPError as e:
        return "", e.code
    except Exception:
        return "", 0


def _base_url(target: str) -> str:
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    return f"https://{target}"


def _is_sensitive(path: str) -> tuple:
    """Returns (is_sensitive, reason)."""
    p = path.lower()
    for pattern in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, p):
            return True, f"Matches sensitive pattern: '{pattern}'"
    return False, ""


def _parse_robots(content: str) -> tuple:
    """Parse robots.txt into (disallowed, allowed, sitemaps)."""
    disallowed, allowed, sitemaps = [], [], []
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                allowed.append(path)
        elif line.lower().startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url:
                sitemaps.append(url)
    return disallowed, allowed, sitemaps


def _parse_sitemap(content: str, base: str) -> list:
    """Extract URLs from sitemap XML."""
    urls = []
    try:
        # Strip namespace
        content_clean = re.sub(r'\s+xmlns[^"]*"[^"]*"', '', content)
        root = ET.fromstring(content_clean)
        for elem in root.iter():
            if elem.tag.endswith("loc") and elem.text:
                url = elem.text.strip()
                # Convert to path only
                path = url.replace(base, "")
                if path and path != url:  # Was a relative path
                    urls.append(path)
                else:
                    urls.append(url)
    except Exception:
        # Fallback: regex
        urls = re.findall(r"<loc>([^<]+)</loc>", content)
    return urls[:100]


def scan(target: str, probe_common_files: bool = True) -> RobotsScan:
    """
    Main entry point.
    """
    base = _base_url(target)
    result = RobotsScan(target=target)
    discovered = []

    # ── robots.txt ─────────────────────────────────────────────────────────
    robots_content, robots_code = _get(f"{base}/robots.txt")
    if robots_code == 200 and robots_content:
        result.robots_txt = robots_content[:5000]
        disallowed, allowed, sitemaps = _parse_robots(robots_content)
        result.disallowed_paths = disallowed
        result.allowed_paths    = allowed
        result.sitemap_urls     = sitemaps

        # Flag sensitive disallowed paths
        for path in disallowed:
            sens, reason = _is_sensitive(path)
            discovered.append(asdict(DiscoveredPath(
                path=path, source="robots.txt",
                sensitive=sens, reason=reason
            )))

        # ── Parse each linked sitemap ──────────────────────────────────────
        for sitemap_url in sitemaps[:3]:
            if not sitemap_url.startswith("http"):
                sitemap_url = base + sitemap_url
            sm_content, sm_code = _get(sitemap_url)
            if sm_code == 200 and sm_content:
                paths = _parse_sitemap(sm_content, base)
                for p in paths[:30]:
                    sens, reason = _is_sensitive(p)
                    discovered.append(asdict(DiscoveredPath(
                        path=p, source="sitemap.xml",
                        sensitive=sens, reason=reason
                    )))

    # ── Probe common files ────────────────────────────────────────────────
    if probe_common_files:
        for path in COMMON_FILES:
            content, code = _get(f"{base}{path}")
            if code == 200:
                result.files_found.append(path)
                sens, reason = _is_sensitive(path)
                discovered.append(asdict(DiscoveredPath(
                    path=path, source="common-file",
                    status_code=code, sensitive=sens, reason=reason
                )))
                # Store security.txt content
                if "security.txt" in path and content:
                    result.security_txt = content[:1000]

    result.discovered_paths = discovered
    result.sensitive_paths  = [d for d in discovered if d.get("sensitive")]
    result.total_paths      = len(discovered)

    return result