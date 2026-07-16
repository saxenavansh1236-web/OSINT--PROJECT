"""
cross_case_correlation.py — Finds overlap between the current target/scan
and other cases already stored in case_management, based on shared
indicators (emails, domains, usernames, IPs, phone numbers, breach names).

Pure comparison logic against data you already have in cases' scan_data —
no external calls, no new API keys.

Usage:
    from cross_case_correlation import correlate_cases
    result["cross_case_correlation"] = correlate_cases(target, result, all_cases)
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class CaseOverlap:
    case_id:          int
    case_title:       str
    shared_indicators: list[dict] = field(default_factory=list)
    overlap_score:    int = 0

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "case_title": self.case_title,
            "shared_indicators": self.shared_indicators,
            "overlap_score": self.overlap_score,
        }


def _extract_indicators(target: str, scan_data: dict) -> dict[str, set]:
    """Pull a flat set of comparable indicators out of a scan_data dict."""
    scan_data = scan_data or {}
    indicators: dict[str, set] = {
        "target": set(), "ip": set(), "email": set(),
        "domain": set(), "username": set(), "phone": set(), "breach": set(),
    }

    if target:
        indicators["target"].add(target.lower())

    ip = scan_data.get("ip")
    if ip and ip != "Not found":
        indicators["ip"].add(str(ip).lower())

    for u in scan_data.get("username") or []:
        name = u.get("name") if isinstance(u, dict) else u
        if name:
            indicators["username"].add(str(name).lower())

    for b in scan_data.get("breach") or []:
        name = (b.get("name") or b.get("breach_name")) if isinstance(b, dict) else b
        if name:
            indicators["breach"].add(str(name).lower())

    rel = scan_data.get("related_entities") or {}
    if isinstance(rel, dict):
        for e in rel.get("emails") or []:
            indicators["email"].add(str(e).lower())
        for d in rel.get("domains") or []:
            indicators["domain"].add(str(d).lower())
        for u in rel.get("usernames") or []:
            name = u.get("name") if isinstance(u, dict) else u
            if name:
                indicators["username"].add(str(name).lower())

    phone = scan_data.get("phone") or {}
    if isinstance(phone, dict) and phone.get("e164"):
        indicators["phone"].add(str(phone["e164"]).lower())

    subs = scan_data.get("subs") or []
    for s in subs:
        host = s.get("host", str(s)) if isinstance(s, dict) else s
        if host:
            indicators["domain"].add(str(host).lower())

    return indicators


_WEIGHTS = {
    "target": 0,     # comparing a case to itself doesn't count
    "phone": 25,
    "email": 20,
    "domain": 15,
    "username": 10,
    "ip": 15,
    "breach": 5,
}


def correlate_cases(target: str, scan_data: dict, all_cases: list,
                     exclude_case_id: int | None = None) -> dict:
    """
    Compares the current target/scan against every case in all_cases and
    returns cases that share at least one indicator, ranked by overlap.

    Args:
        target:          current scan target string.
        scan_data:        current scan result dict.
        all_cases:        list of case dicts (from case_management.list_cases()).
        exclude_case_id:  optional case id to skip (e.g. when correlating a
                          case's own scan against all other cases).
    """
    current = _extract_indicators(target, scan_data)

    overlaps: list[CaseOverlap] = []

    for case in all_cases or []:
        case_id = case.get("id")
        if exclude_case_id is not None and case_id == exclude_case_id:
            continue

        case_target = case.get("target", "")
        case_scan   = case.get("scan_data") or {}
        other = _extract_indicators(case_target, case_scan)

        shared = []
        score = 0
        for kind, values in current.items():
            if kind == "target":
                continue
            common = values & other.get(kind, set())
            if common:
                weight = _WEIGHTS.get(kind, 5)
                score += weight * len(common)
                shared.append({"type": kind, "values": sorted(common)})

        if shared:
            overlaps.append(CaseOverlap(
                case_id=case_id,
                case_title=case.get("title", f"Case #{case_id}"),
                shared_indicators=shared,
                overlap_score=min(score, 100),
            ))

    overlaps.sort(key=lambda o: o.overlap_score, reverse=True)

    return {
        "target": target,
        "total_correlated_cases": len(overlaps),
        "overlaps": [o.to_dict() for o in overlaps[:20]],
    }