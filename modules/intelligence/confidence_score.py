"""
modules/intelligence/confidence_score.py
-----------------------------------------
Confidence Score + Risk Analysis for a case, driven by the case's own
`scan_data` (the dict produced by run_osint_scan() in app.py) plus any
investigator notes attached to the case.

Public entry point: analyze_case(case, notes) -> IntelligenceResult
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


@dataclass
class IntelligenceResult:
    confidence: int              # 0-100
    risk_level: str               # LOW / MEDIUM / HIGH / CRITICAL
    risk_score: int                # 0-100, raw points behind the level
    signals: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "signals": self.signals,
            "warnings": self.warnings,
        }


def _as_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        try:
            return obj.to_dict() or {}
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    return {}


def _as_list(obj: Any) -> List[Any]:
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    try:
        return list(obj)
    except Exception:
        return []


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def _safe_len(x) -> int:
    try:
        return len(x)
    except Exception:
        return 0


def _extract_signals(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Pull normalized signal values out of an arbitrary run_osint_scan() result."""
    scan_data = scan_data or {}

    breaches = scan_data.get("breach") or []
    usernames = scan_data.get("username") or []
    subs = scan_data.get("subs") or []

    dark = scan_data.get("dark") or {}
    dark_flagged = bool(dark.get("flagged")) if isinstance(dark, dict) else False
    dark_findings = _safe_len(dark.get("findings")) if isinstance(dark, dict) else 0

    vt = scan_data.get("virustotal") or {}
    vt_malicious = vt.get("malicious", 0) if isinstance(vt, dict) else 0

    otx = scan_data.get("otx") or {}
    otx_pulses = otx.get("pulse_count", 0) if isinstance(otx, dict) else 0

    abuse = scan_data.get("abuse") or {}
    abuse_score = abuse.get("abuse_confidence_score", 0) if isinstance(abuse, dict) else 0

    port_scan = scan_data.get("port_scan") or {}
    risky_ports = _safe_len(port_scan.get("risky_ports")) if isinstance(port_scan, dict) else 0

    paste = scan_data.get("paste_monitor") or {}
    paste_mentions = _safe_len(paste.get("mentions")) if isinstance(paste, dict) else 0

    dd = scan_data.get("directory_discovery") or {}
    sensitive_paths = _safe_len(dd.get("sensitive_found")) if isinstance(dd, dict) else 0

    whois = scan_data.get("whois") or {}
    has_whois = bool(whois) and "error" not in whois
    has_ip = bool(scan_data.get("ip")) and scan_data.get("ip") != "Not found"
    has_geo = isinstance(scan_data.get("geo"), dict) and "error" not in scan_data.get("geo", {})
    has_dns = isinstance(scan_data.get("dns"), dict) and "error" not in scan_data.get("dns", {})
    has_ssl = isinstance(scan_data.get("ssl"), dict) and "error" not in scan_data.get("ssl", {})

    return {
        "breach_count": _safe_len(breaches),
        "username_hits": _safe_len(usernames),
        "subdomain_count": _safe_len(subs),
        "dark_flagged": dark_flagged,
        "dark_findings": dark_findings,
        "vt_malicious": vt_malicious,
        "otx_pulses": otx_pulses,
        "abuse_score": abuse_score,
        "risky_ports": risky_ports,
        "paste_mentions": paste_mentions,
        "sensitive_paths": sensitive_paths,
        "has_whois": has_whois,
        "has_ip": has_ip,
        "has_geo": has_geo,
        "has_dns": has_dns,
        "has_ssl": has_ssl,
    }


def _compute_confidence(signals: Dict[str, Any]) -> int:
    """
    Confidence = how much verifiable, corroborated data we actually have
    on the target — NOT how dangerous it is. A clean, well-resolved
    domain with full WHOIS/DNS/SSL/subdomain data scores high confidence
    even if risk is low.
    """
    points = 0.0
    max_points = 0.0

    checks = [
        ("has_whois", 15),
        ("has_ip", 10),
        ("has_geo", 10),
        ("has_dns", 15),
        ("has_ssl", 10),
    ]
    for key, weight in checks:
        max_points += weight
        if signals.get(key):
            points += weight

    # corroboration from multiple independent sources
    max_points += 20
    corroboration = 0
    if signals["breach_count"] > 0:
        corroboration += 1
    if signals["username_hits"] > 0:
        corroboration += 1
    if signals["subdomain_count"] > 0:
        corroboration += 1
    if signals["vt_malicious"] or signals["otx_pulses"]:
        corroboration += 1
    points += min(corroboration, 4) * 5

    # data volume bonus (more subdomains/usernames = richer picture)
    max_points += 20
    volume_score = _clamp((signals["subdomain_count"] + signals["username_hits"]) / 20.0)
    points += volume_score * 20

    if max_points == 0:
        return 0
    return round(_clamp(points / max_points) * 100)


def _compute_risk(signals: Dict[str, Any]) -> Tuple[int, str]:
    """
    Risk = threat/severity signals. Independent axis from confidence:
    a target can be low-confidence (little data) and still flagged
    HIGH risk off a single strong signal (e.g. dark web flag).
    """
    score = 0

    if signals["dark_flagged"]:
        score += 30
    score += min(signals["dark_findings"] * 5, 15)

    score += min(signals["breach_count"] * 4, 20)

    if signals["vt_malicious"]:
        score += min(signals["vt_malicious"] * 5, 20)

    score += min(signals["otx_pulses"] * 3, 15)
    score += min(int(signals["abuse_score"]) // 10, 10)
    score += min(signals["risky_ports"] * 4, 12)
    score += min(signals["paste_mentions"] * 5, 10)
    score += min(signals["sensitive_paths"] * 3, 9)

    score = min(score, 100)

    if score >= 60:
        level = "CRITICAL"
    elif score >= 35:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def _build_warnings(signals: Dict[str, Any]) -> List[str]:
    warnings = []
    if signals["dark_flagged"]:
        warnings.append("Target flagged on dark web monitoring.")
    if signals["breach_count"] > 0:
        warnings.append(f"{signals['breach_count']} known data breach(es) associated with target.")
    if signals["vt_malicious"]:
        warnings.append(f"VirusTotal flagged {signals['vt_malicious']} malicious detection(s).")
    if signals["otx_pulses"]:
        warnings.append(f"{signals['otx_pulses']} AlienVault OTX threat pulse(s) reference this target.")
    if signals["risky_ports"]:
        warnings.append(f"{signals['risky_ports']} risky open port(s) detected.")
    if signals["paste_mentions"]:
        warnings.append(f"{signals['paste_mentions']} paste-site mention(s) found.")
    if signals["sensitive_paths"]:
        warnings.append(f"{signals['sensitive_paths']} sensitive path(s) discovered.")
    if not signals["has_whois"] and not signals["has_dns"]:
        warnings.append("Limited resolvable infrastructure data — confidence may be low.")
    return warnings


def analyze_case(case: Dict[str, Any], notes: List[Any] = None) -> IntelligenceResult:
    """
    Main entry point. `case` is expected to be dict-like (from
    case_management.get_case()) with a `scan_data` key holding the raw
    OSINT scan result. Defensive against SQLAlchemy row objects, None,
    or malformed scan_data — always returns a valid IntelligenceResult
    rather than raising.
    """
    case = _as_dict(case)
    notes = _as_list(notes)

    scan_data = case.get("scan_data")
    scan_data = _as_dict(scan_data)

    try:
        signals = _extract_signals(scan_data)
        confidence = _compute_confidence(signals)
        risk_score, risk_level = _compute_risk(signals)
    except Exception:
        signals = {}
        confidence = 0
        risk_score = 0
        risk_level = "LOW"

    # Active investigator notes are themselves a corroboration signal
    note_count = _safe_len(notes)
    if note_count > 0:
        confidence = round(_clamp((confidence / 100) + min(note_count, 5) * 0.02) * 100)

    try:
        warnings = _build_warnings(signals)
    except Exception:
        warnings = []

    return IntelligenceResult(
        confidence=confidence,
        risk_level=risk_level,
        risk_score=risk_score,
        signals=signals,
        warnings=warnings,
    )