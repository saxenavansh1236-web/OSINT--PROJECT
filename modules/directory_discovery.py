"""
directory_discovery.py
Discover public directories and files on a target domain.
"""

import requests
import threading
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common directories to probe
COMMON_DIRS = [
    "/admin", "/administrator", "/admin/login", "/admin/dashboard",
    "/login", "/signin", "/signup", "/register",
    "/api", "/api/v1", "/api/v2", "/api/docs", "/swagger", "/swagger-ui.html",
    "/graphql", "/graphiql",
    "/dashboard", "/panel", "/cpanel", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/mysql", "/database",
    "/backup", "/backups", "/bak", "/old", "/archive",
    "/uploads", "/upload", "/files", "/file", "/media",
    "/images", "/img", "/static", "/assets", "/public",
    "/config", "/conf", "/configuration", "/settings",
    "/.env", "/.git", "/.git/config", "/.svn", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/security.txt", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/web.config", "/app.config", "/composer.json", "/package.json",
    "/readme.md", "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/server-status", "/server-info", "/_profiler", "/debug",
    "/logs", "/log", "/error_log", "/access_log",
    "/tmp", "/temp", "/cache",
    "/test", "/tests", "/dev", "/development",
    "/shell", "/cmd", "/console",
    "/metrics", "/health", "/healthz", "/status", "/ping",
    "/docs", "/documentation", "/wiki",
    "/store", "/shop", "/cart", "/checkout",
    "/user", "/users", "/account", "/accounts", "/profile",
    "/mail", "/email", "/webmail",
    "/ftp", "/sftp",
    "/jenkins", "/gitlab", "/bitbucket", "/jira", "/confluence",
    "/wordpress", "/drupal", "/joomla", "/magento",
    "/.DS_Store", "/thumbs.db",
]

SENSITIVE_KEYWORDS = [
    "admin", "login", "backup", "config", ".env", ".git",
    "phpmyadmin", "database", "shell", "cmd", "console",
    "debug", "logs", "tmp", "test", "dev", "jenkins",
    "api/v", "swagger", "graphql", "server-status",
    "wp-admin", "wp-login", "cpanel",
]

# Lowered from 20 -> 8. This is I/O-bound work (each thread makes a full
# HTTP request via `requests`), so fewer concurrent threads only adds a
# modest amount of wall-clock time to the scan, but meaningfully reduces
# peak memory (each thread carries its own connection/SSL overhead). This
# was contributing to OOM worker kills on memory-constrained hosts (e.g.
# Render free tier's 512MB).
DEFAULT_THREADS = 8


@dataclass
class DiscoveredPath:
    path: str
    status_code: int
    content_length: int = 0
    content_type: str = ""
    redirect_url: str = ""
    sensitive: bool = False
    reason: str = ""
    response_time_ms: float = 0.0

    def to_dict(self):
        return asdict(self)


@dataclass
class DirectoryResult:
    target: str
    total_checked: int = 0
    found: List[DiscoveredPath] = field(default_factory=list)
    sensitive_found: List[DiscoveredPath] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self):
        return {
            "target": self.target,
            "total_checked": self.total_checked,
            "found_count": len(self.found),
            "sensitive_count": len(self.sensitive_found),
            "found": [p.to_dict() for p in self.found],
            "sensitive_found": [p.to_dict() for p in self.sensitive_found],
            "summary": self.summary,
        }


def _is_sensitive(path: str) -> tuple:
    path_lower = path.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in path_lower:
            return True, f"Contains sensitive keyword: '{kw}'"
    return False, ""


def _probe_path(base_url: str, path: str, timeout: int = 5) -> Optional[DiscoveredPath]:
    url = base_url.rstrip("/") + path
    try:
        import time
        start = time.time()
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; OSINTScanner/1.0)",
            },
        )
        elapsed = (time.time() - start) * 1000

        # Skip 404s and other not-found responses
        if resp.status_code in (404, 410):
            return None

        # Some servers return 200 for everything — filter by content length
        content_length = len(resp.content)
        if resp.status_code == 200 and content_length < 10:
            return None

        sensitive, reason = _is_sensitive(path)
        redirect_url = resp.headers.get("Location", "")

        return DiscoveredPath(
            path=path,
            status_code=resp.status_code,
            content_length=content_length,
            content_type=resp.headers.get("Content-Type", ""),
            redirect_url=redirect_url,
            sensitive=sensitive,
            reason=reason,
            response_time_ms=round(elapsed, 1),
        )
    except requests.exceptions.SSLError:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


def discover(target: str, threads: int = DEFAULT_THREADS, custom_paths: List[str] = None, timeout: int = 5) -> DirectoryResult:
    """
    Discover public directories and files on a target domain.

    Args:
        target: Domain or URL (e.g. 'example.com' or 'https://example.com')
        threads: Number of concurrent threads
        custom_paths: Additional paths to check
        timeout: Request timeout in seconds

    Returns:
        DirectoryResult dataclass
    """
    # Normalise target to base URL
    if not target.startswith(("http://", "https://")):
        base_url = f"https://{target}"
    else:
        base_url = target

    paths_to_check = list(COMMON_DIRS)
    if custom_paths:
        paths_to_check.extend(custom_paths)

    result = DirectoryResult(target=target)
    result.total_checked = len(paths_to_check)

    found = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_probe_path, base_url, path, timeout): path
            for path in paths_to_check
        }
        for future in as_completed(futures):
            discovered = future.result()
            if discovered:
                with lock:
                    found.append(discovered)

    # Sort by status code then path
    found.sort(key=lambda x: (x.status_code, x.path))
    result.found = found
    result.sensitive_found = [p for p in found if p.sensitive]

    counts = {}
    for p in found:
        counts[p.status_code] = counts.get(p.status_code, 0) + 1

    summary_parts = [f"{cnt} × {code}" for code, cnt in sorted(counts.items())]
    result.summary = (
        f"Found {len(found)} accessible paths out of {len(paths_to_check)} checked. "
        f"{len(result.sensitive_found)} sensitive. "
        + (", ".join(summary_parts) if summary_parts else "")
    )

    return result
