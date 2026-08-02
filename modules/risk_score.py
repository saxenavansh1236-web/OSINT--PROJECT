import re
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class RiskFactor:
    name: str
    score: int
    severity: str
    category: str
    detail: str = ""


@dataclass
class RiskScore:
    target: str
    total_score: int = 0
    risk_level: str = "Low"
    factors: list = field(default_factory=list)
    categories: dict = field(default_factory=dict)
    recommendations: list = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def _risk_level(score: int) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 40: return "Medium"
    if score >= 20: return "Low"
    return "Minimal"


# ── Target-type self-correction ──────────────────────────────────────────
# Mirrors app.py's own _is_email/_is_phone/_is_domain logic, duplicated
# here (rather than imported, to avoid a circular import with app.py) so
# this module never trusts "a key happens to be present in scan_result" as
# proof that a factor type is actually applicable. This is the same
# self-correction principle already applied in leak_checker.py v3: a
# domain-only signal (SPF/DMARC) must never be scored against a target
# that isn't actually a domain or email, regardless of what stray keys
# might be sitting in the scan_result dict.
def _is_email(target: str) -> bool:
    return "@" in target and "." in target.split("@")[-1]


def _is_phone(target: str) -> bool:
    cleaned = re.sub(r"[\s\-().]+", "", target)
    return bool(re.match(r"^\+?\d{7,15}$", cleaned))


def _is_domain(target: str) -> bool:
    return "." in target and not _is_email(target) and not _is_phone(target)


# Confidence multiplier: how much weight to give a finding based on how
# solid the underlying match actually is. Unverified + non-email matches
# (e.g. a broad domain-wide LeakCheck.io hit) are downweighted rather
# than treated as equal to a confirmed HIBP breach on a real mailbox.
def _confidence_multiplier(breach: dict) -> float:
    verified = bool(breach.get("verified", False))
    ttype = breach.get("target_type", "email")
    if verified:
        return 1.0
    if ttype == "email":
        return 0.8   # unverified but at least tied to a real mailbox
    return 0.4       # unverified AND not a confirmed email match (domain/broad)


# Ceiling on how many raw points the "breaches" category can contribute,
# applied before the global 0-100 clamp. Prevents one noisy source (e.g.
# 40+ broad domain-wide matches) from single-handedly maxing the score.
_BREACH_CATEGORY_CAP = 45

# Ceiling on how many raw points the "leaks" category (from the separate
# result["leak"] key, distinct from result["breach"]) can contribute.
# Kept lower than the breach cap since this data overlaps with — and is
# often the exact same underlying signal as — the breaches category.
_LEAK_CATEGORY_CAP = 15


def calculate(target: str, scan_result: dict) -> RiskScore:
    """
    Main entry point. Pass the full scan result dict from run_osint_scan().
    Returns a RiskScore with 0-100 total score and factor breakdown.
    """
    result = RiskScore(target=target)
    factors = []
    raw_score = 0
    cats = {}

    # Determine the target's real type ONCE, up front, so every
    # type-specific section below can gate on it explicitly instead of
    # inferring type from "does this key happen to exist."
    target_is_domain = _is_domain(target)
    target_is_email = _is_email(target)
    target_is_phone = _is_phone(target)

    def add(name, pts, severity, category, detail=""):
        nonlocal raw_score
        factors.append(asdict(RiskFactor(
            name=name, score=pts, severity=severity,
            category=category, detail=detail
        )))
        raw_score += pts
        cats[category] = cats.get(category, 0) + pts

    # ── Breaches (confidence-weighted, category-capped) ───────────────────
    breaches = scan_result.get("breach", [])
    breach_category_total = 0
    if isinstance(breaches, list):
        sev_pts = {"critical": 15, "high": 10, "medium": 6, "low": 3, "info": 1}
        for b in breaches[:10]:
            if isinstance(b, dict):
                sev = b.get("severity", "high")
                base_pts = sev_pts.get(sev, 5)
                weighted_pts = round(base_pts * _confidence_multiplier(b))

                if breach_category_total >= _BREACH_CATEGORY_CAP:
                    break  # category cap reached — stop adding more breach points
                weighted_pts = min(weighted_pts, _BREACH_CATEGORY_CAP - breach_category_total)
                breach_category_total += weighted_pts

                confidence_note = "" if b.get("verified") else " (unverified match)"
                add(f"Breach: {b.get('name', 'Unknown')}{confidence_note}",
                    weighted_pts, sev, "breaches",
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

    # ── SSL issues (domain-only — a phone/username/IP scan has no SSL) ────
    ssl = scan_result.get("ssl", {})
    if target_is_domain and isinstance(ssl, dict):
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

    # ── Open risky ports (domain/IP-only) ──────────────────────────────────
    port_scan = scan_result.get("port_scan", {})
    if target_is_domain and isinstance(port_scan, dict):
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

    # ── Security headers (domain-only) ─────────────────────────────────────
    headers = scan_result.get("headers_analysis", {})
    if target_is_domain and isinstance(headers, dict):
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

    # ── DNS issues (domain or email-domain-part ONLY) ──────────────────────
    # This is the section that was previously firing for ANY target that
    # happened to have a stray "dns" key in scan_result — including phone
    # number scans, where SPF/DMARC are meaningless. Gated on
    # target_is_domain / target_is_email now, exactly like leak_checker.py's
    # v3 type self-correction: a signal that only makes sense for one
    # target type can never silently apply to another.
    dns = scan_result.get("dns", {})
    if (target_is_domain or target_is_email) and isinstance(dns, dict):
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

    # ── Phone-specific risk factors (phone-only) ───────────────────────────
    phone = scan_result.get("phone", {})
    if target_is_phone and isinstance(phone, dict) and not phone.get("error"):
        if not phone.get("valid"):
            add("Phone number failed validity check", 10, "medium", "phone")

        vd = phone.get("validity_detail", {})
        if isinstance(vd, dict) and vd.get("is_possible") and not vd.get("is_valid"):
            add("Phone: possible-but-invalid number", 6, "medium", "phone",
                "Format-correct but fails carrier-range validation")

        if phone.get("is_disposable"):
            add("Phone: disposable/virtual-number carrier", 8, "medium", "phone")
        elif phone.get("is_voip"):
            add("Phone: VOIP carrier", 4, "low", "phone")

        pf = phone.get("pattern_flags", {})
        if isinstance(pf, dict):
            if pf.get("is_sequential"):
                add("Phone: sequential digit pattern", 5, "low", "phone")
            if pf.get("is_repeated_digit"):
                add("Phone: repeated-digit pattern", 4, "low", "phone")

        scam = phone.get("scam", {})
        if isinstance(scam, dict) and scam.get("fraud_score", "").lower() in ("medium", "high"):
            pts = 12 if scam["fraud_score"].lower() == "high" else 6
            tag = "provider" if scam.get("source") == "provider" else "heuristic"
            add(f"Phone: {scam['fraud_score']} fraud signal ({tag})", pts, "high", "phone")

    # ── Leaks (from leak_check_all — a SEPARATE scan-result key from
    #    "breach" above, so this must stay independently capped or it
    #    double-counts the same underlying findings when both fire) ──────
    leak = scan_result.get("leak", {})
    if isinstance(leak, dict) and not leak.get("error"):
        sev_sum = leak.get("severity_summary", {}) or {}
        crit = sev_sum.get("critical", 0)
        high = sev_sum.get("high", 0)
        med  = sev_sum.get("medium", 0)
        info = sev_sum.get("info", 0)

        # Weight by actual severity mix, not raw count. Previously this
        # used total_leaks * 3 (capped at 20) regardless of whether those
        # leaks were verified breaches or unverified domain-wide guesses
        # — meaning 15 low-confidence "medium" leaks scored the same as
        # 15 confirmed critical ones. Only critical/high leaks drive
        # meaningful points now; medium/info (the domain-wide unverified
        # case) contribute much less, matching the confidence weighting
        # already applied to the "breach" category above.
        weighted = (crit * 5) + (high * 3) + (med * 0.5) + (info * 0.1)
        pts = min(round(weighted), _LEAK_CATEGORY_CAP)
        total_leaks = leak.get("total_leaks", 0)
        if pts > 0:
            add(f"{total_leaks} leak(s) found "
                f"({crit} critical, {high} high, {med} medium, {info} info)",
                pts, "high" if (crit or high) else "medium", "leaks")

    # ── Subdomains (domain-only) ────────────────────────────────────────────
    subs = scan_result.get("subs", [])
    if target_is_domain and isinstance(subs, list) and len(subs) > 20:
        add(f"Large attack surface: {len(subs)} subdomains",
            min(len(subs) // 5, 10), "medium", "attack_surface",
            "More subdomains = more potential entry points")

    # ── Tech stack exposure (domain-only) ──────────────────────────────────
    tech = scan_result.get("tech", {})
    if target_is_domain and isinstance(tech, dict):
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
    if any(f["category"] == "phone" for f in factors):
        recs.append("Treat VOIP/disposable-carrier numbers with reduced trust; verify identity through a second channel before acting on requests from this number.")
    result.recommendations = recs

    result.summary = (
        f"Risk Level: {result.risk_level} ({result.total_score}/100). "
        f"{len(factors)} risk factor(s) identified across {len(cats)} categories."
    )

    return result
