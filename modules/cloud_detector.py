"""
cloud_detector.py
Detect cloud provider (AWS, Azure, GCP, Cloudflare, etc.) for a target domain/IP.
Uses IP range lookups, DNS patterns, HTTP headers, and CNAME analysis.
"""

import re
import socket
import ipaddress
import requests
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINTScanner/1.0)"}

# ── Known CNAME / hostname patterns ──────────────────────────────────────────
CNAME_PATTERNS: Dict[str, List[str]] = {
    "AWS CloudFront":    [r"\.cloudfront\.net$"],
    "AWS S3":            [r"\.s3\.amazonaws\.com$", r"\.s3-website.*\.amazonaws\.com$"],
    "AWS ELB":           [r"\.elb\.amazonaws\.com$", r"\.amazonaws\.com$"],
    "AWS EC2":           [r"\.compute\.amazonaws\.com$", r"\.ec2\.amazonaws\.com$"],
    "Azure":             [r"\.azurewebsites\.net$", r"\.azure\.com$", r"\.cloudapp\.azure\.com$",
                          r"\.trafficmanager\.net$", r"\.azureedge\.net$", r"\.blob\.core\.windows\.net$"],
    "GCP":               [r"\.appspot\.com$", r"\.googleusercontent\.com$",
                          r"\.run\.app$", r"\.cloudfunctions\.net$", r"\.googleapis\.com$"],
    "Cloudflare":        [r"\.cdn\.cloudflare\.net$", r"cloudflare\.com$"],
    "Fastly":            [r"\.fastly\.net$", r"\.fastlylb\.net$"],
    "Akamai":            [r"\.akamaiedge\.net$", r"\.akamai\.net$", r"\.akadns\.net$"],
    "Vercel":            [r"\.vercel\.app$", r"\.now\.sh$", r"\.vercel\.com$"],
    "Netlify":           [r"\.netlify\.app$", r"\.netlify\.com$"],
    "GitHub Pages":      [r"\.github\.io$", r"\.github\.com$"],
    "Heroku":            [r"\.herokuapp\.com$", r"\.heroku\.com$"],
    "DigitalOcean":      [r"\.digitaloceanspaces\.com$"],
    "Render":            [r"\.onrender\.com$"],
    "Railway":           [r"\.railway\.app$"],
}

# ── HTTP header fingerprints ──────────────────────────────────────────────────
HEADER_PATTERNS: Dict[str, Dict[str, str]] = {
    "Cloudflare":  {"server": "cloudflare", "cf-ray": ""},
    "AWS":         {"x-amz-request-id": "", "x-amzn-requestid": "", "x-amz-id-2": ""},
    "Azure":       {"x-ms-request-id": "", "x-azure-ref": "", "x-msedge-ref": ""},
    "GCP":         {"x-goog-request-id": "", "via": "1.1 google"},
    "Vercel":      {"x-vercel-id": ""},
    "Netlify":     {"x-nf-request-id": "", "server": "netlify"},
    "Fastly":      {"x-served-by": "cache", "fastly-restarts": ""},
    "Akamai":      {"x-check-cacheable": "", "x-akamai-request-id": ""},
}

# ── Known IP ranges (sampled — full ranges fetched dynamically when possible) ─
KNOWN_IP_RANGES: Dict[str, List[str]] = {
    "Cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "AWS": [
        "3.0.0.0/9", "13.32.0.0/15", "13.248.0.0/16",
        "15.177.0.0/18", "18.0.0.0/8", "34.192.0.0/10",
        "52.0.0.0/8", "54.0.0.0/8",
    ],
    "GCP": [
        "8.34.208.0/20", "8.35.192.0/20", "23.236.48.0/20",
        "23.251.128.0/19", "34.0.0.0/9", "35.184.0.0/13",
        "64.233.160.0/19", "66.102.0.0/20",
    ],
    "Azure": [
        "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14",
        "20.0.0.0/8", "40.64.0.0/10", "51.0.0.0/8",
        "52.96.0.0/12", "104.40.0.0/13",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "117.82.27.0/24", "151.101.0.0/16",
        "157.52.64.0/18", "167.82.0.0/17",
    ],
}


@dataclass
class CloudProvider:
    name: str
    confidence: str          # high / medium / low
    detection_methods: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class CloudDetectResult:
    target: str
    ip: str = ""
    resolved_cname: str = ""
    providers: List[CloudProvider] = field(default_factory=list)
    primary_provider: str = "Unknown"
    is_proxied: bool = False
    cdn_detected: bool = False
    http_headers: Dict = field(default_factory=dict)
    summary: str = ""

    def to_dict(self):
        return {
            "target": self.target,
            "ip": self.ip,
            "resolved_cname": self.resolved_cname,
            "primary_provider": self.primary_provider,
            "is_proxied": self.is_proxied,
            "cdn_detected": self.cdn_detected,
            "providers": [p.to_dict() for p in self.providers],
            "http_headers": self.http_headers,
            "summary": self.summary,
        }


def _resolve_cname(domain: str) -> str:
    """Resolve CNAME chain for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        pass
    # Fallback: simple socket lookup
    try:
        return socket.getfqdn(domain)
    except Exception:
        return ""


def _resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def _check_ip_range(ip: str) -> List[str]:
    """Return list of cloud providers whose ranges contain this IP."""
    matched = []
    try:
        ip_obj = ipaddress.ip_address(ip)
        for provider, ranges in KNOWN_IP_RANGES.items():
            for cidr in ranges:
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        matched.append(provider)
                        break
                except ValueError:
                    continue
    except ValueError:
        pass
    return matched


def _check_cname_patterns(cname: str) -> List[str]:
    """Return cloud providers matching CNAME patterns."""
    matched = []
    if not cname:
        return matched
    for provider, patterns in CNAME_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, cname, re.IGNORECASE):
                matched.append(provider)
                break
    return matched


def _fetch_headers(target: str, timeout: int = 7) -> Dict:
    """Fetch HTTP response headers from target."""
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{target}"
            resp = requests.head(url, headers=HEADERS, timeout=timeout,
                                 allow_redirects=True)
            return {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            continue
    return {}


def _detect_from_headers(headers: Dict) -> List[str]:
    matched = []
    for provider, patterns in HEADER_PATTERNS.items():
        for header_key, header_val in patterns.items():
            if header_key in headers:
                if not header_val or header_val.lower() in headers[header_key].lower():
                    matched.append(provider)
                    break
    return matched


def detect(target: str, timeout: int = 7) -> CloudDetectResult:
    """
    Detect cloud provider for a target domain or IP.

    Args:
        target: Domain or IP address
        timeout: HTTP request timeout

    Returns:
        CloudDetectResult dataclass
    """
    # Clean target
    domain = re.sub(r"^https?://", "", target).split("/")[0].split("?")[0]

    result = CloudDetectResult(target=target)

    # 1. Resolve IP
    ip = _resolve_ip(domain)
    result.ip = ip

    # 2. Resolve CNAME
    cname = _resolve_cname(domain)
    result.resolved_cname = cname if cname != domain else ""

    # 3. Check HTTP headers
    headers = _fetch_headers(domain, timeout)
    result.http_headers = {
        k: v for k, v in headers.items()
        if k in ("server", "via", "x-powered-by", "cf-ray", "x-amz-request-id",
                 "x-ms-request-id", "x-goog-request-id", "x-vercel-id",
                 "x-nf-request-id", "x-check-cacheable", "x-akamai-request-id",
                 "x-azure-ref", "x-served-by", "x-cache", "age", "x-amzn-requestid")
    }

    # 4. Collect evidence
    provider_evidence: Dict[str, List[str]] = {}

    # IP ranges
    if ip:
        for p in _check_ip_range(ip):
            provider_evidence.setdefault(p, []).append(f"IP {ip} in {p} range")

    # CNAME
    if cname:
        for p in _check_cname_patterns(cname):
            provider_evidence.setdefault(p, []).append(f"CNAME: {cname}")

    # Headers
    for p in _detect_from_headers(headers):
        provider_evidence.setdefault(p, []).append("HTTP headers")

    # CDN detection
    cdn_providers = {"Cloudflare", "Fastly", "Akamai", "AWS CloudFront"}
    result.cdn_detected = any(p in cdn_providers for p in provider_evidence)

    # Cloudflare proxied detection
    if "cf-ray" in headers or "Cloudflare" in provider_evidence:
        result.is_proxied = True

    # Build CloudProvider objects with confidence
    providers = []
    for name, methods in provider_evidence.items():
        confidence = "high" if len(methods) >= 2 else "medium" if len(methods) == 1 else "low"
        providers.append(CloudProvider(
            name=name,
            confidence=confidence,
            detection_methods=methods,
        ))

    # Sort by confidence
    conf_order = {"high": 0, "medium": 1, "low": 2}
    providers.sort(key=lambda x: conf_order.get(x.confidence, 3))
    result.providers = providers

    # Primary provider
    if providers:
        result.primary_provider = providers[0].name
    else:
        result.primary_provider = "Unknown / Self-hosted"

    # Summary
    provider_names = [p.name for p in providers]
    if provider_names:
        result.summary = (
            f"Detected: {', '.join(provider_names)}. "
            f"Primary: {result.primary_provider}. "
            f"{'CDN/Proxy detected. ' if result.cdn_detected else ''}"
            f"IP: {ip or 'N/A'}"
        )
    else:
        result.summary = f"No cloud provider detected. IP: {ip or 'N/A'}. May be self-hosted."

    return result