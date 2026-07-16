"""
timeline.py — Build a chronological investigation event timeline
Aggregates data from all OSINT modules into a unified timeline.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import re


@dataclass
class TimelineEvent:
    date: str               # ISO date string or "Unknown"
    year: str = ""
    category: str = ""      # breach / dns / ssl / archive / whois / threat / leak / phone
    event_type: str = ""    # e.g. "Domain registered", "Breach: LinkedIn"
    detail: str = ""
    severity: str = "info"  # critical / high / medium / low / info
    source: str = ""
    icon: str = "📌"


@dataclass
class InvestigationTimeline:
    target: str
    events: list = field(default_factory=list)  # TimelineEvent dicts, sorted by date
    date_range: dict = field(default_factory=dict)
    total_events: int = 0
    categories: dict = field(default_factory=dict)  # category → count
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


# ── Severity icon map ──────────────────────────────────────────────────────
SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

CATEGORY_ICONS = {
    "breach":   "🔓",
    "dns":      "🌐",
    "ssl":      "🔒",
    "archive":  "📦",
    "whois":    "📋",
    "threat":   "🛡",
    "leak":     "💧",
    "port":     "🔌",
    "subdomain":"🔗",
    "tech":     "⚙️",
    "employee": "👤",
    "dns_history": "📜",
    "phone":    "📱",
}


def _normalise_date(raw: str) -> tuple:
    """
    Try to parse various date formats into (iso_date, year).
    Returns ("Unknown", "") on failure.
    """
    if not raw:
        return "Unknown", ""

    raw = str(raw).strip()

    # Already ISO
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if m:
        return raw[:10], raw[:4]

    # Year-Month only
    m = re.match(r"(\d{4})-(\d{2})$", raw)
    if m:
        return f"{m.group(1)}-{m.group(2)}-01", m.group(1)

    # Year only
    m = re.match(r"(\d{4})$", raw)
    if m:
        return f"{m.group(1)}-01-01", m.group(1)

    # DD/MM/YYYY or MM/DD/YYYY
    m = re.match(r"(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})", raw)
    if m:
        return f"{m.group(3)}-{m.group(2).zfill(2)}-{m.group(1).zfill(2)}", m.group(3)

    return "Unknown", ""


def _add(events: list, date_raw: str, category: str, event_type: str,
         detail: str = "", severity: str = "info", source: str = ""):
    iso, year = _normalise_date(date_raw)
    events.append(asdict(TimelineEvent(
        date=iso,
        year=year,
        category=category,
        event_type=event_type,
        detail=detail,
        severity=severity,
        source=source,
        icon=CATEGORY_ICONS.get(category, "📌"),
    )))


def build(target: str, scan_result: dict) -> InvestigationTimeline:
    """
    Build a timeline from a full OSINT scan result dict.

    Args:
        target:      The scanned target string
        scan_result: The dict returned by run_osint_scan() in app.py
    """
    tl = InvestigationTimeline(target=target)
    events = []

    # ── WHOIS dates ────────────────────────────────────────────────────────
    whois = scan_result.get("whois", {})
    if isinstance(whois, dict) and not whois.get("error"):
        if whois.get("creation_date"):
            _add(events, whois["creation_date"], "whois",
                 "Domain Registered",
                 f"Registrar: {whois.get('registrar', 'Unknown')}",
                 severity="info", source="WHOIS")
        if whois.get("updated_date"):
            _add(events, whois["updated_date"], "whois",
                 "Domain Updated",
                 "WHOIS record last modified", severity="info", source="WHOIS")
        if whois.get("expiry_date"):
            _add(events, whois["expiry_date"], "whois",
                 "Domain Expiry",
                 "Registration expires", severity="low", source="WHOIS")

    # ── SSL certificate ────────────────────────────────────────────────────
    ssl = scan_result.get("ssl", {})
    if isinstance(ssl, dict) and not ssl.get("error"):
        if ssl.get("not_before"):
            _add(events, ssl["not_before"], "ssl",
                 "SSL Certificate Issued",
                 f"Issuer: {ssl.get('issuer_cn', 'Unknown')}",
                 severity="info", source="SSL")
        if ssl.get("not_after"):
            sev = "high" if ssl.get("expired") else ("medium" if ssl.get("expiring_soon") else "info")
            _add(events, ssl["not_after"], "ssl",
                 "SSL Certificate Expires",
                 f"Days remaining: {ssl.get('days_remaining', '?')}",
                 severity=sev, source="SSL")

    # ── Breaches ───────────────────────────────────────────────────────────
    breaches = scan_result.get("breach", [])
    if isinstance(breaches, list):
        for b in breaches:
            if isinstance(b, dict):
                date  = b.get("date", "")
                name  = b.get("name", "Unknown breach")
                sev   = b.get("severity", "high")
                recs  = b.get("records", 0)
                detail = f"{name}"
                if recs:
                    detail += f" — {recs:,} records"
                _add(events, date, "breach", f"Data Breach: {name}",
                     detail, severity=sev, source=b.get("source", "Breach DB"))

    # ── Leaks ──────────────────────────────────────────────────────────────
    leak = scan_result.get("leak", {})
    if isinstance(leak, dict) and not leak.get("error"):
        for l in (leak.get("leaks") or []):
            if isinstance(l, dict):
                _add(events, l.get("date", ""), "leak",
                     f"Leak: {l.get('breach_name', 'Unknown')}",
                     l.get("description", ""),
                     severity=l.get("severity", "medium"),
                     source=l.get("source", "Leak DB"))

    # ── Web archive ────────────────────────────────────────────────────────
    archive = scan_result.get("archive", {})
    if isinstance(archive, dict) and not archive.get("error"):
        if archive.get("first_seen"):
            _add(events, archive["first_seen"], "archive",
                 "First Web Archive Snapshot",
                 f"Total snapshots: {archive.get('total_snapshots', '?')}",
                 severity="info", source="Wayback Machine")
        if archive.get("last_seen"):
            _add(events, archive["last_seen"], "archive",
                 "Latest Web Archive Snapshot",
                 "", severity="info", source="Wayback Machine")
        # Per-year snapshots
        for yr, count in (archive.get("snapshots_by_year") or {}).items():
            _add(events, f"{yr}-06-01", "archive",
                 f"Archive Activity: {yr}",
                 f"{count} snapshots", severity="info", source="Wayback Machine")

    # ── Threat / dark web ─────────────────────────────────────────────────
    dark = scan_result.get("dark", {})
    if isinstance(dark, dict):
        for f in (dark.get("findings") or []):
            if isinstance(f, dict):
                label = f.get("malware") or f.get("threat_type") or "Threat"
                _add(events, "", "threat", f"Threat Intel: {label}",
                     f.get("detail", ""), severity="high",
                     source=f.get("source", "Threat DB"))

    # ── DNS history ────────────────────────────────────────────────────────
    dns_hist = scan_result.get("dns_history", {})
    if isinstance(dns_hist, dict):
        for rec in (dns_hist.get("historical_ips") or []):
            if isinstance(rec, dict) and rec.get("first_seen"):
                _add(events, rec["first_seen"], "dns_history",
                     f"IP Change: {rec.get('ip', '?')}",
                     f"Org: {rec.get('org', 'Unknown')}",
                     severity="info", source=rec.get("source", "PassiveDNS"))

    # ── Phone-specific events ───────────────────────────────────────────────
    # Pulls from modules/phone_lookup.py output only — no new API calls.
    # Adds: scam/fraud report date, breaches linked via phone correlation,
    # and a dateless WhatsApp registration marker (WhatsApp gives no
    # registration date via the public wa.me check, so it's flagged
    # "Unknown" and sorts after dated events, same as other undated items).
    phone = scan_result.get("phone", {})
    if isinstance(phone, dict) and not phone.get("error"):
        scam = phone.get("scam") or {}
        if isinstance(scam, dict) and scam.get("available") and scam.get("last_reported"):
            tag = "provider" if scam.get("source") == "provider" else "heuristic"
            _add(events, scam["last_reported"], "phone",
                 "Scam/Fraud Report Filed",
                 f"Fraud score ({tag}): {scam.get('fraud_score', '?')}",
                 severity="high" if scam.get("fraud_score") == "High" else "medium",
                 source="Scam Intelligence")

        corr = phone.get("correlation") or {}
        if isinstance(corr, dict):
            for lk in (corr.get("leaks") or []):
                if isinstance(lk, dict):
                    name = lk.get("breach_name") or lk.get("name") or "Unknown breach"
                    _add(events, lk.get("date", ""), "phone",
                         f"Breach Linked to Number: {name}",
                         ", ".join(lk.get("data_classes", [])),
                         severity=lk.get("severity", "high"),
                         source=lk.get("source", "phone_lookup.py correlation"))

        wa = phone.get("whatsapp") or {}
        if isinstance(wa, dict) and wa.get("checked") and wa.get("registered") is True:
            _add(events, "", "phone",
                 "WhatsApp Registration Detected",
                 "Confirmed via public wa.me check — no registration date available",
                 severity="info", source=wa.get("method", "wa.me public link"))

        carrier_detail = phone.get("carrier_detail") or {}
        if isinstance(carrier_detail, dict) and carrier_detail.get("available") and carrier_detail.get("ported"):
            _add(events, "", "phone",
                 "Number Porting Detected",
                 "Number appears to have changed carriers",
                 severity="medium", source="HLR provider")

    # ── Sort events: known dates first, then Unknown ───────────────────────
    def sort_key(e):
        d = e.get("date", "Unknown")
        return ("0" if d != "Unknown" else "1") + d

    events.sort(key=sort_key)

    tl.events = events
    tl.total_events = len(events)

    # ── Date range ─────────────────────────────────────────────────────────
    dated = [e["date"] for e in events if e["date"] != "Unknown"]
    if dated:
        tl.date_range = {"earliest": dated[0], "latest": dated[-1]}

    # ── Category counts ────────────────────────────────────────────────────
    cats = {}
    for e in events:
        c = e.get("category", "other")
        cats[c] = cats.get(c, 0) + 1
    tl.categories = cats

    return tl