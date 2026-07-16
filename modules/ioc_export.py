"""
ioc_export.py — Builds IOC (Indicator of Compromise) records from a scan
result and exports them as STIX 2.1 bundle JSON or MISP-compatible event
JSON. Pure data formatting — no external calls, no new API keys.

Supports 5 IOC types:
  - ipv4-addr   (IP addresses)
  - domain-name (domains)
  - url         (URLs, e.g. from urlscan results)
  - file-hash   (MD5 / SHA1 / SHA256, e.g. from image hashing / OTX IOCs)
  - email-addr  (email addresses)
  plus phone-number and username as extensions specific to this platform.

Usage (single-IOC, backward compatible):
    from ioc_export import build_ioc, to_stix, to_misp
    ioc = build_ioc(target, result)
    stix_json = to_stix(ioc)
    misp_json = to_misp(ioc)

Usage (multi-IOC, new — pulls every distinct indicator out of one scan):
    from ioc_export import build_iocs_multi, to_stix_bundle, to_misp_event_multi
    iocs = build_iocs_multi(target, result)
    stix_json = to_stix_bundle(iocs)
    misp_json = to_misp_event_multi(target, iocs)
"""

from __future__ import annotations
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ─────────────────────────────────────────────
# IOC type detection / validation helpers
# ─────────────────────────────────────────────

_IPV4_RE   = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE    = re.compile(r"^https?://", re.IGNORECASE)


def _classify_hash(value: str) -> str | None:
    if _MD5_RE.match(value):
        return "md5"
    if _SHA1_RE.match(value):
        return "sha1"
    if _SHA256_RE.match(value):
        return "sha256"
    return None


def _infer_ioc_type(target: str, result: dict) -> str:
    phone = result.get("phone")
    if isinstance(phone, dict) and phone.get("valid"):
        return "phone-number"
    if "@" in target and "." in target.split("@")[-1]:
        return "email-addr"
    if _URL_RE.match(target):
        return "url"
    if _classify_hash(target):
        return "file-hash"
    if _IPV4_RE.match(target):
        return "ipv4-addr"
    if result.get("whois") or result.get("dns") or "." in target:
        return "domain-name"
    return "username" if target else "unknown"


# ─────────────────────────────────────────────
# Single IOC record (primary target)
# ─────────────────────────────────────────────

@dataclass
class IOCRecord:
    ioc_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    ioc_type:   str = "unknown"   # ipv4-addr | domain-name | url | file-hash | email-addr | phone-number | username
    value:      str = ""
    hash_algo:  str | None = None  # md5 | sha1 | sha256, only set when ioc_type == "file-hash"
    risk_score: int = 0
    risk_level: str = "Low"
    confidence: str = "LOW"
    tags:       list[str] = field(default_factory=list)
    created:    str = field(default_factory=_now_iso)
    source:     str = "OSINT Investigation Platform"

    def to_dict(self) -> dict:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "hash_algo": self.hash_algo,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "tags": self.tags,
            "created": self.created,
            "source": self.source,
        }


def build_ioc(target: str, result: dict) -> IOCRecord:
    """Primary-target IOC — same behavior as before, kept for backward compatibility."""
    ioc = IOCRecord()
    ioc.value = target
    ioc.ioc_type = _infer_ioc_type(target, result)
    if ioc.ioc_type == "file-hash":
        ioc.hash_algo = _classify_hash(target)

    rs = result.get("risk_score") or {}
    if isinstance(rs, dict):
        ioc.risk_score = rs.get("total_score", 0)
        ioc.risk_level = rs.get("risk_level", "Low")

    ident = result.get("identity_score") or {}
    if isinstance(ident, dict):
        ioc.confidence = ident.get("confidence", "MINIMAL")

    tags = []
    dark = result.get("dark") or {}
    if isinstance(dark, dict) and dark.get("flagged"):
        tags.append("flagged")
    if result.get("breach"):
        tags.append("breached")
    vt = result.get("virustotal") or {}
    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        tags.append("malicious")
    otx = result.get("otx") or {}
    if isinstance(otx, dict):
        tags.extend((otx.get("tags") or [])[:5])
    ioc.tags = sorted(set(tags))

    return ioc


# ─────────────────────────────────────────────
# Multi-IOC extraction — pulls every distinct
# indicator type out of a single scan result
# ─────────────────────────────────────────────

def _base_ioc(value: str, ioc_type: str, risk_score: int, risk_level: str,
              confidence: str, tags: list[str], source: str,
              hash_algo: str | None = None) -> IOCRecord:
    return IOCRecord(
        value=value, ioc_type=ioc_type, hash_algo=hash_algo,
        risk_score=risk_score, risk_level=risk_level, confidence=confidence,
        tags=sorted(set(tags)), source=source,
    )


def build_iocs_multi(target: str, result: dict) -> list[IOCRecord]:
    """
    Extracts every distinct IOC this scan touched — not just the primary
    target — so a single domain/phone/email scan can enrich blue-team
    tooling with IPs, related domains, URLs, file hashes, and emails all
    at once. De-duplicated by (type, value).
    """
    rs = result.get("risk_score") or {}
    risk_score = rs.get("total_score", 0) if isinstance(rs, dict) else 0
    risk_level = rs.get("risk_level", "Low") if isinstance(rs, dict) else "Low"

    ident = result.get("identity_score") or {}
    confidence = ident.get("confidence", "MINIMAL") if isinstance(ident, dict) else "MINIMAL"

    base_tags = []
    dark = result.get("dark") or {}
    if isinstance(dark, dict) and dark.get("flagged"):
        base_tags.append("flagged")
    if result.get("breach"):
        base_tags.append("breached")

    seen: set[tuple[str, str]] = set()
    iocs: list[IOCRecord] = []

    def add(value: str, ioc_type: str, extra_tags: list[str] | None = None,
             source: str = "OSINT Investigation Platform", hash_algo: str | None = None):
        if not value:
            return
        key = (ioc_type, value.lower())
        if key in seen:
            return
        seen.add(key)
        iocs.append(_base_ioc(
            value=value, ioc_type=ioc_type,
            risk_score=risk_score, risk_level=risk_level, confidence=confidence,
            tags=base_tags + (extra_tags or []), source=source, hash_algo=hash_algo,
        ))

    # ── Primary target ──
    add(target, _infer_ioc_type(target, result), source="Primary target")

    # ── IP address(es) ──
    ip = result.get("ip")
    if ip and ip != "Not found" and _IPV4_RE.match(ip):
        add(ip, "ipv4-addr", source="reverse_ip.py / geo.py")

    vt = result.get("virustotal") or {}
    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        extra = ["malicious", "virustotal"]
        add(target, _infer_ioc_type(target, result), extra_tags=extra, source="VirusTotal")

    abuse = result.get("abuse") or {}
    if isinstance(abuse, dict) and abuse.get("ip_address"):
        tags = ["malicious"] if abuse.get("total_reports", 0) > 0 else []
        add(abuse["ip_address"], "ipv4-addr", extra_tags=tags, source="AbuseIPDB")

    otx = result.get("otx") or {}
    if isinstance(otx, dict):
        for ioc_entry in (otx.get("iocs") or []):
            h = ioc_entry.get("hash") if isinstance(ioc_entry, dict) else None
            if h:
                algo = _classify_hash(h) or "unknown"
                add(h, "file-hash", extra_tags=["otx", "malware"], source="AlienVault OTX", hash_algo=algo)
        for dns_rec in (otx.get("dns_records") or []):
            if isinstance(dns_rec, dict) and dns_rec.get("address"):
                if _IPV4_RE.match(dns_rec["address"]):
                    add(dns_rec["address"], "ipv4-addr", source="OTX passive DNS")
                elif dns_rec.get("hostname"):
                    add(dns_rec["hostname"], "domain-name", source="OTX passive DNS")

    # ── Domain(s) ──
    subs = result.get("subs") or []
    for s in subs[:20]:
        host = s.get("host") if isinstance(s, dict) else s
        if host:
            add(host, "domain-name", source="subdomain.py")

    related = result.get("related_entities") or {}
    if isinstance(related, dict):
        for d in (related.get("domains") or []):
            add(d, "domain-name", source="related_entities.py")
        for e in (related.get("emails") or []):
            add(e, "email-addr", source="related_entities.py")

    # ── URL(s) — from URLScan and Screenshot ──
    us = result.get("urlscan") or {}
    if isinstance(us, dict):
        page_url = us.get("page_url") or us.get("scan_url")
        if page_url:
            tags = ["malicious"] if us.get("malicious") else []
            add(page_url, "url", extra_tags=tags, source="URLScan.io")

    shot = result.get("screenshot") or {}
    if isinstance(shot, dict) and shot.get("final_url"):
        add(shot["final_url"], "url", source="screenshot.py")

    # ── File hash(es) — from Image Intel hashing (if scan came via image path) ──
    img_intel = result.get("image_intel") or {}
    if isinstance(img_intel, dict):
        hashes = img_intel.get("hashes") or {}
        if isinstance(hashes, dict) and hashes.get("available"):
            for algo in ("md5", "sha256"):
                h = hashes.get(algo)
                if h:
                    add(h, "file-hash", source="image_hashing.py", hash_algo=algo)

    # ── Email(s) ──
    email_osint = result.get("email_osint") or {}
    if isinstance(email_osint, dict) and email_osint.get("valid_format") and "@" in target:
        add(target, "email-addr", source="email.py")

    return iocs


# ─────────────────────────────────────────────
# STIX 2.1 export
# ─────────────────────────────────────────────

_STIX_PATTERN_MAP = {
    "phone-number": lambda ioc: f"[phone-number:value = '{ioc.value}']",
    "email-addr":   lambda ioc: f"[email-addr:value = '{ioc.value}']",
    "domain-name":  lambda ioc: f"[domain-name:value = '{ioc.value}']",
    "ipv4-addr":    lambda ioc: f"[ipv4-addr:value = '{ioc.value}']",
    "url":          lambda ioc: f"[url:value = '{ioc.value}']",
    "file-hash":    lambda ioc: f"[file:hashes.'{(ioc.hash_algo or 'SHA-256').upper()}' = '{ioc.value}']",
    "username":     lambda ioc: f"[user-account:account_login = '{ioc.value}']",
}

_STIX_CONF_MAP = {"HIGH": 90, "MEDIUM": 60, "LOW": 30, "MINIMAL": 10}


def _stix_indicator(ioc: IOCRecord) -> dict:
    pattern_fn = _STIX_PATTERN_MAP.get(ioc.ioc_type, lambda i: f"[artifact:payload_bin = '{i.value}']")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{ioc.ioc_id}",
        "created": ioc.created,
        "modified": ioc.created,
        "name": f"OSINT finding: {ioc.value}",
        "pattern": pattern_fn(ioc),
        "pattern_type": "stix",
        "valid_from": ioc.created,
        "confidence": _STIX_CONF_MAP.get(ioc.confidence, 30),
        "labels": ioc.tags or ["osint-lead"],
        "description": f"Risk score {ioc.risk_score}/100 ({ioc.risk_level}). Source: {ioc.source}.",
    }


def to_stix(ioc: IOCRecord) -> str:
    """Single-indicator STIX bundle (backward compatible)."""
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [_stix_indicator(ioc)],
    }
    return json.dumps(bundle, indent=2)


def to_stix_bundle(iocs: list[IOCRecord]) -> str:
    """Multi-indicator STIX bundle — one bundle, many indicator objects."""
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [_stix_indicator(ioc) for ioc in iocs],
    }
    return json.dumps(bundle, indent=2)


# ─────────────────────────────────────────────
# MISP-compatible export
# ─────────────────────────────────────────────

_MISP_TYPE_MAP = {
    "phone-number": "phone-number",
    "email-addr":   "email-src",
    "domain-name":  "domain",
    "ipv4-addr":    "ip-dst",
    "url":          "url",
    "username":     "target-user",
}

_MISP_HASH_TYPE_MAP = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}

_MISP_THREAT_MAP = {"Low": "4", "Medium": "3", "High": "2", "Critical": "1"}


def _misp_attribute(ioc: IOCRecord) -> dict:
    if ioc.ioc_type == "file-hash":
        misp_type = _MISP_HASH_TYPE_MAP.get(ioc.hash_algo or "", "sha256")
    else:
        misp_type = _MISP_TYPE_MAP.get(ioc.ioc_type, "text")
    return {
        "type": misp_type,
        "category": "External analysis",
        "value": ioc.value,
        "to_ids": ioc.risk_score >= 50,
        "comment": f"Risk {ioc.risk_score}/100 · Confidence {ioc.confidence} · Source: {ioc.source}",
    }


def to_misp(ioc: IOCRecord) -> str:
    """Single-indicator MISP event (backward compatible)."""
    event = {
        "Event": {
            "uuid": ioc.ioc_id,
            "info": f"OSINT finding: {ioc.value}",
            "date": ioc.created[:10],
            "threat_level_id": _MISP_THREAT_MAP.get(ioc.risk_level, "4"),
            "analysis": "1",
            "distribution": "0",
            "Attribute": [_misp_attribute(ioc)],
            "Tag": [{"name": t} for t in ioc.tags],
        }
    }
    return json.dumps(event, indent=2)


def to_misp_event_multi(target: str, iocs: list[IOCRecord]) -> str:
    """Multi-indicator MISP event — one event, many attributes."""
    if not iocs:
        return json.dumps({"Event": {"info": f"OSINT finding: {target}", "Attribute": []}}, indent=2)

    highest_risk = max((i.risk_score for i in iocs), default=0)
    risk_level = next((i.risk_level for i in iocs if i.risk_score == highest_risk), "Low")
    all_tags = sorted(set(t for i in iocs for t in i.tags))

    event = {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": f"OSINT investigation: {target}",
            "date": iocs[0].created[:10],
            "threat_level_id": _MISP_THREAT_MAP.get(risk_level, "4"),
            "analysis": "1",
            "distribution": "0",
            "Attribute": [_misp_attribute(ioc) for ioc in iocs],
            "Tag": [{"name": t} for t in all_tags],
        }
    }
    return json.dumps(event, indent=2)