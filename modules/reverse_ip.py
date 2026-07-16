"""
reverse_ip.py — Resolve any target to an IP address.

Delegates all DNS resolution to dns_lookup.lookup() so there is no
duplicated socket/DoH logic.  Previously this file reimplemented
gethostbyname() and a manual Cloudflare DoH fallback; both are now
handled by dns_lookup which already uses dnspython with a proper
lifetime / error model.

Usage
-----
    from reverse_ip import reverse_lookup, reverse_lookup_all

    ip   = reverse_lookup("example.com")         # → "93.184.216.34"
    ip   = reverse_lookup("user@example.com")    # email → extracts domain
    ip   = reverse_lookup("93.184.216.34")       # already an IP → returns as-is
    all  = reverse_lookup_all("example.com")     # → ["93.184.216.34", …]
"""

from __future__ import annotations

from modules.dns_lookup import lookup   # single source of truth for DNS


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def reverse_lookup(target: str) -> str | None:
    """
    Resolve *target* to its primary IPv4 address.

    Handles:
      - Plain domain      → DNS A record
      - Email address     → extracts domain, then A record
      - Raw IPv4 address  → returned as-is (no lookup needed)
      - Username          → not resolvable, returns None

    Returns the first A record IP, or None if unresolvable.
    """
    if not target:
        return None

    target = target.strip().lower()

    # Email → extract domain
    if "@" in target:
        target = target.split("@")[-1]

    # Already an IP → pass straight through
    if _is_ipv4(target):
        return target

    # Delegate to dns_lookup (handles www fallback, DoH, error suppression)
    result = lookup(target)

    if result.a:
        return result.a[0]

    # dns_lookup already tries the bare domain; if still nothing, give up
    return None


def reverse_lookup_all(target: str) -> list[str]:
    """
    Return *all* IPv4 addresses for *target* (A records).
    Useful when a domain has multiple IPs (round-robin, CDN, etc.).
    """
    if not target:
        return []

    target = target.strip().lower()

    if "@" in target:
        target = target.split("@")[-1]

    if _is_ipv4(target):
        return [target]

    result = lookup(target)
    return result.a or []


def ptr_lookup(ip: str) -> str | None:
    """
    Reverse-DNS a raw IP address → hostname.
    Thin wrapper around dns_lookup's internal _ptr helper, exposed here
    for callers that only have an IP and want the PTR record.
    """
    if not _is_ipv4(ip):
        return None
    result = lookup(ip)          # lookup handles PTR via result.ptr
    return result.ptr[0] if result.ptr else None


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _is_ipv4(s: str) -> bool:
    """Return True if *s* looks like a dotted-quad IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False