"""
related_entities.py — Aggregates possible related entities (emails, domains,
usernames, prior cases) from an already-completed scan result. Pure
aggregation of data you already collect — no new API calls.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class RelatedEntities:
    emails:          list[str] = field(default_factory=list)
    domains:         list[str] = field(default_factory=list)
    usernames:       list[dict] = field(default_factory=list)
    previous_cases:  list[dict] = field(default_factory=list)
    connected_evidence: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "emails": self.emails,
            "domains": self.domains,
            "usernames": self.usernames,
            "previous_cases": self.previous_cases,
            "connected_evidence": self.connected_evidence,
        }


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def _extract_emails(result: dict) -> list[str]:
    found = set()

    emp = result.get("employee") or {}
    if isinstance(emp, dict):
        found.update(emp.get("email_guesses") or [])
        found.update(emp.get("tech_emails") or [])

    eo = result.get("email_osint") or {}
    if isinstance(eo, dict) and eo.get("email"):
        found.add(eo["email"])

    corr = (result.get("phone") or {}).get("correlation") or {}
    found.update(corr.get("emails") or [])

    # Scan any breach/leak dicts for email-shaped fields.
    for coll_key in ("breach", "leak"):
        coll = result.get(coll_key)
        items = coll.get("leaks") if isinstance(coll, dict) else coll
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    val = item.get("email") or item.get("account")
                    if val and _EMAIL_RE.fullmatch(str(val)):
                        found.add(val)

    return sorted(found)


def _extract_domains(result: dict) -> list[str]:
    found = set()

    target = result.get("target", "")
    if _DOMAIN_RE.fullmatch(target):
        found.add(target)

    subs = result.get("subs") or []
    for s in subs:
        host = s.get("host") if isinstance(s, dict) else s
        if host:
            found.add(host)

    emp = result.get("employee") or {}
    if isinstance(emp, dict) and emp.get("company_name"):
        pass  # company name isn't a domain, skip

    ch = result.get("cert_history") or {}
    if isinstance(ch, dict):
        found.update(ch.get("subdomains_discovered") or [])

    otx = result.get("otx") or {}
    if isinstance(otx, dict):
        for d in otx.get("dns_records") or []:
            if isinstance(d, dict) and d.get("hostname"):
                found.add(d["hostname"])

    us = result.get("urlscan") or {}
    if isinstance(us, dict):
        found.update(us.get("domains") or [])

    return sorted(found)


def _extract_usernames(result: dict) -> list[dict]:
    unames = result.get("username") or []
    out = []
    for u in unames:
        if isinstance(u, dict):
            out.append({"name": u.get("name", "?"), "url": u.get("url", ""), "category": u.get("category", "Other")})
    corr = (result.get("phone") or {}).get("correlation") or {}
    for u in corr.get("usernames") or []:
        if isinstance(u, dict):
            entry = {"name": u.get("name", "?"), "url": u.get("url", ""), "category": u.get("category", "Other")}
            if entry not in out:
                out.append(entry)
    return out


def build_related_entities(result: dict, case_lookup=None) -> RelatedEntities:
    """
    Args:
        result:      the scan result dict.
        case_lookup: optional callable(target) -> list[dict] to look up
                     previous cases for the same target (wire in
                     modules.case_management.list_cases if available).
    """
    entities = RelatedEntities()
    entities.emails = _extract_emails(result)
    entities.domains = _extract_domains(result)
    entities.usernames = _extract_usernames(result)

    if case_lookup:
        try:
            target = result.get("target", "")
            entities.previous_cases = case_lookup(target) or []
        except Exception:
            entities.previous_cases = []

    return entities