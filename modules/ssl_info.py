"""
ssl_info.py — SSL/TLS certificate & cipher inspector.

Collects
--------
* Subject / Issuer (CN, O, C)
* Validity window (not_before, not_after, days_remaining)
* SAN domains (Subject Alternative Names)
* Serial number, fingerprints (SHA-1, SHA-256)
* Signature algorithm
* Public key type & size
* Cipher suite & TLS version
* OCSP stapling check
* Certificate chain depth
* CT log presence (via crt.sh)
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

import requests

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "OSINT-Platform/2.0"})
_TIMEOUT = 10


# ─────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────

@dataclass
class SSLResult:
    domain: str
    port: int = 443
    # Certificate fields
    subject_cn: str = ""
    subject_o:  str = ""
    subject_c:  str = ""
    issuer_cn:  str = ""
    issuer_o:   str = ""
    issuer_c:   str = ""
    # Validity
    not_before: str = ""
    not_after:  str = ""
    days_remaining: int = 0
    expired: bool = False
    expiring_soon: bool = False   # < 30 days
    # SANs
    san_domains: list[str] = field(default_factory=list)
    wildcard_sans: list[str] = field(default_factory=list)
    # Fingerprints
    sha1_fingerprint:   str = ""
    sha256_fingerprint: str = ""
    serial_number: str = ""
    # Crypto
    sig_algorithm:  str = ""
    pubkey_type:    str = ""
    pubkey_bits:    int = 0
    # TLS handshake
    tls_version:  str = ""
    cipher_suite: str = ""
    # Chain
    chain_depth:  int = 0
    self_signed:  bool = False
    # CT logs
    ct_log_entries: list[dict] = field(default_factory=list)
    # OCSP
    ocsp_stapled: bool = False
    # Errors
    error: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def inspect(domain: str, port: int = 443) -> SSLResult:
    """Full SSL/TLS certificate inspection for *domain*:*port*."""
    domain = _clean(domain)
    result = SSLResult(domain=domain, port=port)

    try:
        raw_cert, der_bytes, tls_ver, cipher = _get_cert(domain, port)
    except Exception as exc:
        result.error = str(exc)
        return result

    # ── Subject & Issuer ────────────────────────────────────────────────────
    subj = dict(x[0] for x in raw_cert.get("subject", []))
    issuer = dict(x[0] for x in raw_cert.get("issuer", []))
    result.subject_cn = subj.get("commonName", "")
    result.subject_o  = subj.get("organizationName", "")
    result.subject_c  = subj.get("countryName", "")
    result.issuer_cn  = issuer.get("commonName", "")
    result.issuer_o   = issuer.get("organizationName", "")
    result.issuer_c   = issuer.get("countryName", "")

    # ── Validity ────────────────────────────────────────────────────────────
    not_before_str = raw_cert.get("notBefore", "")
    not_after_str  = raw_cert.get("notAfter", "")

    not_before = _parse_cert_date(not_before_str)
    not_after  = _parse_cert_date(not_after_str)
    now = datetime.now(timezone.utc)

    result.not_before = not_before.strftime("%Y-%m-%d") if not_before else not_before_str
    result.not_after  = not_after.strftime("%Y-%m-%d")  if not_after  else not_after_str
    if not_after:
        delta = not_after - now
        result.days_remaining = delta.days
        result.expired        = delta.days < 0
        result.expiring_soon  = 0 <= delta.days < 30

    if result.expired:
        result.warnings.append("Certificate is EXPIRED")
    if result.expiring_soon:
        result.warnings.append(f"Certificate expires in {result.days_remaining} days")

    # ── SANs ────────────────────────────────────────────────────────────────
    san_raw = raw_cert.get("subjectAltName", ())
    sans = [v for t, v in san_raw if t == "DNS"]
    result.san_domains    = sans
    result.wildcard_sans  = [s for s in sans if s.startswith("*.")]

    # ── Fingerprints ────────────────────────────────────────────────────────
    if der_bytes:
        result.sha1_fingerprint   = hashlib.sha1(der_bytes).hexdigest().upper()
        result.sha256_fingerprint = hashlib.sha256(der_bytes).hexdigest().upper()
    result.serial_number = str(raw_cert.get("serialNumber", ""))

    # ── Crypto ──────────────────────────────────────────────────────────────
    result.sig_algorithm = raw_cert.get("signatureAlgorithm", "")

    # ── TLS handshake info ──────────────────────────────────────────────────
    result.tls_version  = tls_ver
    result.cipher_suite = cipher[0] if cipher else ""

    # ── Self-signed check ───────────────────────────────────────────────────
    result.self_signed = (result.subject_cn == result.issuer_cn)
    if result.self_signed:
        result.warnings.append("Self-signed certificate")

    # ── Weak crypto warnings ─────────────────────────────────────────────────
    if result.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        result.warnings.append(f"Weak TLS version: {result.tls_version}")
    if "RC4" in result.cipher_suite or "DES" in result.cipher_suite:
        result.warnings.append(f"Weak cipher: {result.cipher_suite}")

    # ── CT log lookup via crt.sh ─────────────────────────────────────────────
    result.ct_log_entries = _crtsh(domain)

    return result


# ─────────────────────────────────────────────
# Socket / SSL helpers
# ─────────────────────────────────────────────

def _get_cert(domain: str, port: int) -> tuple[dict, Optional[bytes], str, tuple]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE   # we want the cert even if invalid

    with socket.create_connection((domain, port), timeout=_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            raw_cert  = ssock.getpeercert()
            der_bytes = ssock.getpeercert(binary_form=True)
            tls_ver   = ssock.version() or ""
            cipher    = ssock.cipher() or ()
    return raw_cert, der_bytes, tls_ver, cipher


def _parse_cert_date(s: str) -> Optional[datetime]:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


# ─────────────────────────────────────────────
# crt.sh CT log query
# ─────────────────────────────────────────────

def _crtsh(domain: str) -> list[dict]:
    """Query crt.sh for CT log entries. Returns up to 10 most recent."""
    try:
        r = _SESSION.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            return []
        entries = r.json()
        seen: set[str] = set()
        results = []
        for e in entries:
            key = e.get("name_value", "")
            if key and key not in seen:
                seen.add(key)
                results.append({
                    "name_value":  key,
                    "issuer":      e.get("issuer_name", ""),
                    "not_before":  e.get("not_before", "")[:10],
                    "not_after":   e.get("not_after", "")[:10],
                    "logged_at":   e.get("entry_timestamp", "")[:10],
                })
            if len(results) >= 10:
                break
        return results
    except Exception:
        return []


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _clean(domain: str) -> str:
    return domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]