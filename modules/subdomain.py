"""
subdomains.py — Fast concurrent subdomain enumerator.

Features
--------
* 120-entry curated wordlist (vs 40 before)
* Concurrent DNS with configurable workers (default 10 — lowered from 40
  to reduce peak memory usage on memory-constrained hosts like Render's
  free tier, which was causing worker OOM kills)
* Optional HTTPS probe to confirm live web services
* Returns SubdomainResult objects with IP + status
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
import urllib.request
import urllib.error

# ─────────────────────────────────────────────
# Wordlist  (120 entries)
# ─────────────────────────────────────────────

WORDLIST: list[str] = [
    # Core
    "www", "mail", "webmail", "smtp", "pop", "pop3", "imap",
    "ftp", "sftp", "ssh", "rdp",
    # APIs & services
    "api", "api2", "api3", "v1", "v2", "v3",
    "rest", "graphql", "grpc", "ws", "websocket",
    "gateway", "proxy", "edge", "relay",
    # Dev & ops
    "dev", "dev2", "staging", "stg", "stage",
    "test", "test2", "qa", "uat", "demo",
    "sandbox", "sandbox2", "preview",
    "build", "ci", "cd", "jenkins", "gitlab",
    "beta", "alpha", "canary", "release",
    "internal", "intranet",
    # Admin & mgmt
    "admin", "panel", "console", "portal",
    "dashboard", "backoffice", "manage", "mgmt",
    "cpanel", "whm", "plesk", "directadmin",
    "phpmyadmin", "db", "database",
    # Content & media
    "blog", "news", "press", "media",
    "img", "images", "static", "assets",
    "cdn", "cdn2", "upload", "uploads", "files",
    "docs", "docs2", "wiki", "help", "kb",
    "forum", "community", "board",
    "video", "stream", "live",
    # Auth & accounts
    "auth", "login", "sso", "oauth",
    "accounts", "account", "id", "identity",
    "password", "secure", "security",
    # Mobile & apps
    "app", "apps", "mobile", "m",
    "ios", "android", "pwa",
    # Commerce
    "shop", "store", "cart", "checkout",
    "pay", "payment", "payments", "billing",
    "invoice", "orders",
    # Email infra
    "mx", "mx1", "mx2", "smtp2", "mail2",
    "email", "exchange", "autoconfig", "autodiscover",
    "lists", "newsletter",
    # Network / VPN
    "vpn", "vpn2", "remote", "remoteaccess",
    "proxy2", "socks",
    # Monitoring & infra
    "status", "health", "monitor", "metrics",
    "grafana", "kibana", "splunk", "nagios",
    "logs", "logging",
    # Cloud & infra
    "aws", "gcp", "azure",
    "k8s", "kubernetes", "docker",
    "ns", "ns1", "ns2", "dns",
    # Google Workspace patterns
    "calendar", "drive", "meet", "chat", "maps",
    # Misc popular
    "crm", "erp", "hr", "helpdesk", "ticket", "jira",
    "uat2", "legacy", "old", "new", "next",
]

DNS_TIMEOUT = 3   # seconds per lookup
HTTP_TIMEOUT = 4  # seconds per HTTP probe

# Lowered from 40 -> 10. This is I/O-bound work (DNS + HTTP), so fewer
# concurrent threads only adds a modest amount of wall-clock time to the
# scan, but meaningfully reduces peak memory (each thread carries its own
# stack + socket/SSL overhead). This was contributing to OOM worker kills
# on memory-constrained hosts (e.g. Render free tier's 512MB).
MAX_WORKERS  = 10


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class SubdomainResult:
    host: str
    ip: str
    live: bool   # True if HTTP/HTTPS returned any response
    status: int  # HTTP status code, 0 if not probed / no response

    def __str__(self) -> str:
        status_str = f" [{self.status}]" if self.live else ""
        return f"{self.host} → {self.ip}{status_str}"


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def get_subdomains(
    domain: str,
    *,
    wordlist: list[str] | None = None,
    probe_http: bool = True,
    workers: int = MAX_WORKERS,
) -> list[SubdomainResult]:
    """
    Enumerate subdomains of *domain* using DNS resolution.

    Args:
        domain:     Target domain (with or without scheme).
        wordlist:   Override the built-in wordlist.
        probe_http: Also check if the host serves HTTP/HTTPS.
        workers:    Thread-pool size.

    Returns:
        Sorted list of SubdomainResult for live hosts.
    """
    domain = _clean_domain(domain)
    wl = wordlist if wordlist is not None else WORDLIST

    found: list[SubdomainResult] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_resolve, sub, domain, probe_http): sub
            for sub in wl
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda r: r.host)


def scan_custom(
    domain: str,
    extra_words: list[str],
    *,
    probe_http: bool = True,
    workers: int = MAX_WORKERS,
) -> list[SubdomainResult]:
    """Combine built-in wordlist with caller-supplied extras."""
    combined = list(dict.fromkeys(WORDLIST + extra_words))  # preserve order, dedupe
    return get_subdomains(domain, wordlist=combined, probe_http=probe_http, workers=workers)


# ─────────────────────────────────────────────
# Internal
# ─────────────────────────────────────────────

def _clean_domain(raw: str) -> str:
    return (
        raw.strip().lower()
           .replace("https://", "")
           .replace("http://", "")
           .split("/")[0]
    )


def _resolve(sub: str, domain: str, probe_http: bool) -> Optional[SubdomainResult]:
    host = f"{sub}.{domain}"
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        ip = socket.gethostbyname(host)
    except Exception:
        return None

    # DNS hit — optionally probe HTTP
    status = 0
    live = False
    if probe_http:
        status, live = _http_probe(host)

    return SubdomainResult(host=host, ip=ip, live=live, status=status)


def _http_probe(host: str) -> tuple[int, bool]:
    """Try HTTPS then HTTP. Return (status_code, is_live)."""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}",
                headers={"User-Agent": "OSINT-Platform/2.0"},
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.status, True
        except urllib.error.HTTPError as exc:
            return exc.code, True   # got a real HTTP response
        except Exception:
            continue
    return 0, False
