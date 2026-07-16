"""
whois_lookup.py — Richer WHOIS data with fallback to RDAP.

Returns a flat dict with the most useful registrar / registrant fields,
handling multi-value lists cleanly and falling back to RDAP when the
plain-text WHOIS record is thin.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests
import whois as pywhois


_RDAP_BOOTSTRAP = "https://rdap.org/domain/"
_TIMEOUT = 10
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "OSINT-Platform/2.0", "Accept": "application/rdap+json"})


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def whois_data(domain: str) -> dict:
    """
    Return a clean WHOIS / RDAP dict for *domain*.

    Keys always present (value may be "—"):
        registrar, registrar_url, registrar_email, registrar_iana_id,
        registrant_name, registrant_org, registrant_country,
        admin_email, tech_email,
        creation_date, updated_date, expiry_date, age_days,
        name_servers, dnssec, status

    Additional key on error:
        error
    """
    domain = _clean(domain)

    result = _from_pywhois(domain)

    # If pywhois gave us very little, try RDAP
    if _is_thin(result):
        rdap = _from_rdap(domain)
        result = _merge(result, rdap)

    return result


# ─────────────────────────────────────────────
# Source 1 — python-whois
# ─────────────────────────────────────────────

def _from_pywhois(domain: str) -> dict:
    try:
        w = pywhois.whois(domain)

        # Dates
        creation  = _first_date(w.creation_date)
        updated   = _first_date(w.updated_date)
        expiry    = _first_date(w.expiration_date)
        age_days  = _age(creation)

        # Name servers — dedupe & sort
        ns_raw = w.name_servers or []
        name_servers = ", ".join(sorted({str(n).lower().rstrip(".") for n in ns_raw})) or "—"

        # Status — can be a list
        status = _first_str(w.status)

        return {
            "registrar":          _first_str(w.registrar),
            "registrar_url":      _first_str(getattr(w, "registrar_url", None)),
            "registrar_email":    _first_str(getattr(w, "registrar_abuse_contact_email", None)),
            "registrar_iana_id":  _first_str(getattr(w, "registrar_iana_id", None)),
            "registrant_name":    _first_str(getattr(w, "name", None)),
            "registrant_org":     _first_str(getattr(w, "org", None)),
            "registrant_country": _first_str(getattr(w, "country", None)),
            "admin_email":        _first_str(getattr(w, "emails", None)),
            "tech_email":         "—",
            "creation_date":      creation,
            "updated_date":       updated,
            "expiry_date":        expiry,
            "age_days":           str(age_days) if age_days else "—",
            "name_servers":       name_servers,
            "dnssec":             _first_str(getattr(w, "dnssec", None)),
            "status":             status,
        }
    except Exception as exc:
        return {k: "—" for k in _EMPTY_RECORD} | {"error": str(exc)}


# ─────────────────────────────────────────────
# Source 2 — RDAP (JSON, richer data)
# ─────────────────────────────────────────────

def _from_rdap(domain: str) -> dict:
    try:
        r = _SESSION.get(_RDAP_BOOTSTRAP + domain, timeout=_TIMEOUT)
        r.raise_for_status()
        d = r.json()

        entities = d.get("entities", [])
        registrar_ent = _find_entity(entities, "registrar")
        registrant_ent = _find_entity(entities, "registrant")
        admin_ent = _find_entity(entities, "administrative")
        tech_ent  = _find_entity(entities, "technical")

        events = {e["eventAction"]: e["eventDate"][:10]
                  for e in d.get("events", []) if "eventDate" in e}

        ns_list = [
            ns["ldhName"].lower()
            for ns in d.get("nameservers", [])
            if "ldhName" in ns
        ]

        creation = events.get("registration", "—")
        expiry   = events.get("expiration", "—")
        updated  = events.get("last changed", "—")
        age_days = _age_from_str(creation)

        return {
            "registrar":          _rdap_name(registrar_ent),
            "registrar_url":      _rdap_url(registrar_ent),
            "registrar_email":    _rdap_email(registrar_ent),
            "registrar_iana_id":  _rdap_iana_id(registrar_ent, d),
            "registrant_name":    _rdap_name(registrant_ent),
            "registrant_org":     _rdap_org(registrant_ent),
            "registrant_country": _rdap_country(registrant_ent),
            "admin_email":        _rdap_email(admin_ent),
            "tech_email":         _rdap_email(tech_ent),
            "creation_date":      creation,
            "updated_date":       updated,
            "expiry_date":        expiry,
            "age_days":           str(age_days) if age_days else "—",
            "name_servers":       ", ".join(sorted(ns_list)) or "—",
            "dnssec":             _rdap_dnssec(d),
            "status":             ", ".join(d.get("status", [])) or "—",
        }
    except Exception:
        return {}


# ─────────────────────────────────────────────
# RDAP helpers
# ─────────────────────────────────────────────

def _find_entity(entities: list, role: str) -> dict | None:
    for e in entities:
        if role in e.get("roles", []):
            return e
    return None


def _rdap_name(ent: dict | None) -> str:
    if not ent:
        return "—"
    return ent.get("vcardArray", [None, []])[1][1][3] if len(ent.get("vcardArray", [None, []])) > 1 else ent.get("fn", "—")


def _rdap_org(ent: dict | None) -> str:
    if not ent:
        return "—"
    vcard = ent.get("vcardArray", [None, []])[1] if ent else []
    for item in vcard:
        if item[0] == "org":
            return str(item[3])
    return "—"


def _rdap_email(ent: dict | None) -> str:
    if not ent:
        return "—"
    vcard = ent.get("vcardArray", [None, []])[1] if ent else []
    for item in vcard:
        if item[0] == "email":
            return str(item[3])
    return "—"


def _rdap_url(ent: dict | None) -> str:
    if not ent:
        return "—"
    links = ent.get("links", [])
    for lnk in links:
        if lnk.get("rel") == "self":
            return lnk.get("href", "—")
    return links[0].get("href", "—") if links else "—"


def _rdap_country(ent: dict | None) -> str:
    if not ent:
        return "—"
    vcard = ent.get("vcardArray", [None, []])[1] if ent else []
    for item in vcard:
        if item[0] == "adr":
            adr = item[3]
            if isinstance(adr, list) and len(adr) >= 6:
                return adr[6] or "—"
    return "—"


def _rdap_iana_id(ent: dict | None, root: dict) -> str:
    if ent:
        return str(ent.get("handle", "—"))
    return str(root.get("handle", "—"))


def _rdap_dnssec(root: dict) -> str:
    ds = root.get("secureDNS", {})
    return "signed" if ds.get("delegationSigned") else "unsigned"


# ─────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────

def _clean(raw: str) -> str:
    return raw.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]


def _first_str(val: Any) -> str:
    if val is None:
        return "—"
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return "—"
    return str(val).strip() or "—"


def _first_date(val: Any) -> str:
    if val is None:
        return "—"
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return "—"
    try:
        return val.strftime("%Y-%m-%d")
    except Exception:
        return str(val)[:10]


def _age(date_str: str) -> int | None:
    if date_str == "—":
        return None
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _age_from_str(s: str) -> int | None:
    if not s or s == "—":
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _is_thin(d: dict) -> bool:
    """True if pywhois returned mostly empty fields."""
    meaningful = [v for k, v in d.items() if k != "error" and v != "—"]
    return len(meaningful) < 4


def _merge(base: dict, rdap: dict) -> dict:
    """Fill in '—' fields from rdap."""
    merged = dict(base)
    for k, v in rdap.items():
        if merged.get(k, "—") == "—" and v and v != "—":
            merged[k] = v
    return merged


_EMPTY_RECORD = {
    "registrar": "—", "registrar_url": "—", "registrar_email": "—",
    "registrar_iana_id": "—", "registrant_name": "—", "registrant_org": "—",
    "registrant_country": "—", "admin_email": "—", "tech_email": "—",
    "creation_date": "—", "updated_date": "—", "expiry_date": "—",
    "age_days": "—", "name_servers": "—", "dnssec": "—", "status": "—",
}