"""
risk_score.py — Calculate a composite risk score (0-100) for a target
Aggregates signals from all OSINT modules into a single risk profile.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class RiskFactor:
    name: str
    score: int          # points added (0–100 scale before normalisation)
    severity: str       # critical / high / medium / low / info
    category: str
    detail: str = ""


@dataclass
class RiskScore:
    target: str
    total_score: int = 0         # 0-100
    risk_level: str = "Low"      # Critical / High / Medium / Low / Info
    factors: list = field(default_factory=list)      # RiskFactor dicts
    categories: dict = field(default_factory=dict)   # category → score
    recommendations: list = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


# ── Risk level thresholds ─────────────────────────────────────────────────
def _risk_level(score: int) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 40: return "Medium"
    if score >= 20: return "Low"
    return "Minimal"


def calculate(target: str, scan_result: dict) -> RiskScore:
    """
    Main entry point. Pass the full scan result dict from run_osint_scan().
    Returns a RiskScore with 0-100 total score and factor breakdown.
    """
    result = RiskScore(target=target)
    factors = []
    raw_score = 0
    cats = {}

    def add(name, pts, severity, category, detail=""):
        nonlocal raw_score
        factors.append(asdict(RiskFactor(
            name=name, score=pts, severity=severity,
            category=category, detail=detail
        )))
        raw_score += pts
        cats[category] = cats.get(category, 0) + pts

    # ── Breaches ───────────────────────────────────────────────────────────
    breaches = scan_result.get("breach", [])
    if isinstance(breaches, list):
        sev_pts = {"critical": 15, "high": 10, "medium": 6, "low": 3, "info": 1}
        for b in breaches[:10]:
            if isinstance(b, dict):
                sev = b.get("severity", "high")
                pts = sev_pts.get(sev, 5)
                add(f"Breach: {b.get('name', 'Unknown')}",
                    pts, sev, "breaches",
                    f"{b.get('records', 0):,} records exposed" if b.get("records") else "")

    # ── Threat intel ───────────────────────────────────────────────────────
    dark = scan_result.get("dark", {})
    if isinstance(dark, dict):
        if dark.get("flagged"):
            add("Target flagged in threat intel", 20, "critical", "threat_intel",
                "Active threat listing found")
        threat_score = dark.get("threat_score", 0)
        if threat_score > 0:
            pts = min(int(threat_score / 5), 15)
            add(f"Threat score: {threat_score}/100", pts, "high", "threat_intel")
        for f in (dark.get("findings") or [])[:5]:
            if isinstance(f, dict):
                label = f.get("malware") or f.get("threat_type") or "Finding"
                add(f"Threat: {label}", 8, "high", "threat_intel",
                    f.get("detail", ""))

    # ── SSL issues ─────────────────────────────────────────────────────────
    ssl = scan_result.get("ssl", {})
    if isinstance(ssl, dict):
        if ssl.get("error"):
            add("No SSL certificate", 15, "critical", "ssl",
                "Site accessible over HTTP without encryption")
        elif ssl.get("expired"):
            add("SSL certificate expired", 12, "critical", "ssl",
                f"Expired: {ssl.get('not_after', '?')}")
        elif ssl.get("expiring_soon"):
            add("SSL certificate expiring soon", 6, "medium", "ssl",
                f"Days remaining: {ssl.get('days_remaining', '?')}")
        if ssl.get("self_signed"):
            add("Self-signed certificate", 8, "high", "ssl",
                "No trusted CA — susceptible to MITM")
        tls = ssl.get("tls_version", "")
        if tls and any(v in tls for v in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]):
            add(f"Outdated TLS: {tls}", 10, "high", "ssl",
                "Deprecated protocol — vulnerable to POODLE/BEAST/DROWN")
        for w in (ssl.get("warnings") or []):
            add(f"SSL Warning: {w}", 4, "medium", "ssl")

    # ── Open risky ports ──────────────────────────────────────────────────
    port_scan = scan_result.get("port_scan", {})
    if isinstance(port_scan, dict):
        risky_port_pts = {
            23: (15, "critical", "Telnet — cleartext protocol"),
            21: (10, "high",     "FTP — check for anonymous login"),
            445: (15, "critical", "SMB — EternalBlue/WannaCry surface"),
            3389: (12, "critical", "RDP — brute-force/BlueKeep risk"),
            2375: (20, "critical", "Docker API exposed — RCE risk"),
            6379: (15, "critical", "Redis unauthenticated — data exposure"),
            9200: (12, "high",    "Elasticsearch exposed — data leak"),
            27017: (12, "high",   "MongoDB exposed — often unauthenticated"),
        }
        for port_info in (port_scan.get("risky_ports") or []):
            if isinstance(port_info, dict):
                p = port_info.get("port", 0)
                if p in risky_port_pts:
                    pts, sev, detail = risky_port_pts[p]
                    add(f"Risky open port: {p}/{port_info.get('service', '?')}",
                        pts, sev, "open_ports", detail)

    # ── Security headers ──────────────────────────────────────────────────
    headers = scan_result.get("headers_analysis", {})
    if isinstance(headers, dict):
        missing = headers.get("missing_headers", [])
        if isinstance(missing, list):
            high_missing = [h for h in missing
                            if isinstance(h, dict) and h.get("severity") == "HIGH"]
            med_missing  = [h for h in missing
                            if isinstance(h, dict) and h.get("severity") == "MEDIUM"]
            if high_missing:
                add(f"{len(high_missing)} critical security header(s) missing",
                    len(high_missing) * 5, "high", "security_headers",
                    ", ".join(h.get("header", "") for h in high_missing[:3]))
            if med_missing:
                add(f"{len(med_missing)} medium security header(s) missing",
                    len(med_missing) * 3, "medium", "security_headers")
        if headers.get("info_leaks"):
            leaks = list(headers["info_leaks"].keys())
            add(f"Server info leakage: {', '.join(leaks[:3])}",
                4, "low", "security_headers",
                "Server/framework version exposed in headers")

    # ── DNS issues ─────────────────────────────────────────────────────────
    dns = scan_result.get("dns", {})
    if isinstance(dns, dict):
        if dns.get("zone_transfer"):
            add("DNS zone transfer exposed", 18, "critical", "dns",
                f"{len(dns['zone_transfer'])} records leaked")
        if dns.get("wildcard"):
            add("Wildcard DNS configured", 4, "low", "dns",
                "May mask subdomain enumeration")
        spf = dns.get("spf", {})
        if isinstance(spf, dict) and not spf.get("strict"):
            add("SPF not strict (softfail ~all)", 5, "medium", "dns",
                "Allows email spoofing — change ~all to -all")
        dmarc = dns.get("dmarc", {})
        if isinstance(dmarc, dict) and dmarc.get("policy") == "none":
            add("DMARC policy: none", 6, "medium", "dns",
                "No enforcement — spoofed emails not rejected")

    # ── Leaks ──────────────────────────────────────────────────────────────
    leak = scan_result.get("leak", {})
    if isinstance(leak, dict) and not leak.get("error"):
        total_leaks = leak.get("total_leaks", 0)
        if total_leaks > 0:
            pts = min(total_leaks * 3, 20)
            add(f"{total_leaks} leak(s) found", pts, "high", "leaks")
        sev_sum = leak.get("severity_summary", {})
        if isinstance(sev_sum, dict) and sev_sum.get("critical", 0) > 0:
            add(f"{sev_sum['critical']} critical leak(s)", 15, "critical", "leaks")

    # ── Subdomains ─────────────────────────────────────────────────────────
    subs = scan_result.get("subs", [])
    if isinstance(subs, list) and len(subs) > 20:
        add(f"Large attack surface: {len(subs)} subdomains",
            min(len(subs) // 5, 10), "medium", "attack_surface",
            "More subdomains = more potential entry points")

    # ── Tech stack exposure ───────────────────────────────────────────────
    tech = scan_result.get("tech", {})
    if isinstance(tech, dict):
        outdated_signals = ["wordpress", "drupal 7", "joomla", "php/5", "php/7.0", "php/7.1"]
        for cat in ("cms", "server", "framework"):
            for item in (tech.get(cat) or []):
                if any(s in str(item).lower() for s in outdated_signals):
                    add(f"Potentially outdated technology: {item}",
                        8, "medium", "tech_stack",
                        "Outdated CMS/framework — check for known CVEs")

    # ── Normalise to 0-100 ────────────────────────────────────────────────
    result.total_score  = min(raw_score, 100)
    result.risk_level   = _risk_level(result.total_score)
    result.factors      = sorted(factors, key=lambda x: x["score"], reverse=True)
    result.categories   = cats

    # ── Recommendations ────────────────────────────────────────────────────
    recs = []
    if any(f["category"] == "ssl" for f in factors):
        recs.append("Renew/install SSL certificate and enforce HTTPS with HSTS.")
    if any(f["category"] == "open_ports" for f in factors):
        recs.append("Close unnecessary ports; restrict management ports to VPN/allowlist.")
    if any(f["category"] == "security_headers" for f in factors):
        recs.append("Implement CSP, HSTS, X-Frame-Options, and X-Content-Type-Options headers.")
    if any(f["category"] == "breaches" for f in factors):
        recs.append("Notify affected users; enforce password resets; enable MFA.")
    if any(f["category"] == "dns" for f in factors):
        recs.append("Set SPF to -all (hard fail) and DMARC policy to quarantine or reject.")
    if any(f["category"] == "threat_intel" for f in factors):
        recs.append("Investigate active threat listings; check for malware on hosted infrastructure.")
    result.recommendations = recs

    result.summary = (
        f"Risk Level: {result.risk_level} ({result.total_score}/100). "
        f"{len(factors)} risk factor(s) identified across {len(cats)} categories."
    )

    return result