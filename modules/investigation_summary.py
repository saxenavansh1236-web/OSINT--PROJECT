"""
investigation_summary.py — Generates a plain-English investigation summary
from an already-completed scan result dict. Pure logic, no external calls,
no new API keys required.

Usage:
    from investigation_summary import build_summary
    result["ai_summary"] = build_summary(target, result)
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class InvestigationSummary:
    headline:        str = ""
    paragraphs:      list[str] = field(default_factory=list)
    confidence:      str = "LOW"
    confidence_note: str = ""

    def to_dict(self) -> dict:
        return {
            "headline": self.headline,
            "paragraphs": self.paragraphs,
            "confidence": self.confidence,
            "confidence_note": self.confidence_note,
        }


def _phone_summary(phone: dict) -> list[str]:
    lines = []
    if not phone or phone.get("error"):
        return lines

    valid = phone.get("valid")
    country = phone.get("country_name", "an unknown country")
    carrier = phone.get("carrier_name") or "an unidentified carrier"
    line_type = phone.get("line_type", "unknown")
    region = phone.get("region")

    if valid:
        base = f"The supplied phone number is a valid {line_type} number"
        if country and country != "unknown":
            base += f" registered in {country}"
        if carrier and carrier != "an unidentified carrier":
            base += f", associated with {carrier}"
        if region:
            base += f" (region: {region})"
        base += "."
        lines.append(base)
    else:
        lines.append("The supplied phone number could not be validated against known numbering plans.")

    wa = phone.get("whatsapp") or {}
    if wa.get("checked"):
        reg = wa.get("registered")
        if reg is True:
            lines.append("The number appears to be registered on WhatsApp based on a public presence check.")
        elif reg is False:
            lines.append("The number does not appear to be registered on WhatsApp.")

    corr = phone.get("correlation") or {}
    unames = corr.get("usernames") or []
    leaks = corr.get("leaks") or []
    if unames:
        lines.append(
            f"Cross-correlation surfaced {len(unames)} potential username match(es) on other platforms "
            "using number fragments; these are leads to verify manually, not confirmed identities."
        )
    if leaks:
        lines.append(
            f"The number was associated with {len(leaks)} entry/entries in known data-breach collections."
        )
    elif corr:
        lines.append("No known data-breach associations were found for this number.")

    return lines


def _breach_summary(breach: list) -> list[str]:
    if not breach:
        return ["No publicly indexed breaches were discovered for this target."]
    return [f"{len(breach)} breach record(s) were found referencing this target — review the Breach Check section for details."]


def _username_summary(usernames: list) -> list[str]:
    if not usernames:
        return ["No matching usernames were found across the platforms checked."]
    platforms = ", ".join(sorted({u.get("name", "?") for u in usernames if isinstance(u, dict)})[:6])
    return [f"Username matches were found on {len(usernames)} platform(s), including: {platforms}."]


def _domain_summary(result: dict) -> list[str]:
    lines = []
    dns = result.get("dns") or {}
    ssl = result.get("ssl") or {}
    tech = result.get("tech") or {}

    if isinstance(dns, dict) and not dns.get("error"):
        if dns.get("dnssec"):
            lines.append("DNSSEC is enabled, indicating a hardened DNS configuration.")
        spf = dns.get("spf", {})
        if isinstance(spf, dict) and spf.get("raw") and not spf.get("strict"):
            lines.append("SPF is configured but not set to a strict fail policy, which weakens anti-spoofing protection.")

    if isinstance(ssl, dict) and not ssl.get("error"):
        if ssl.get("expired"):
            lines.append("The SSL certificate has expired.")
        elif ssl.get("expiring_soon"):
            lines.append("The SSL certificate is expiring soon.")

    if isinstance(tech, dict) and tech.get("cms"):
        lines.append(f"The site appears to run on: {', '.join(tech.get('cms', []))}.")

    return lines


def _confidence_from_signals(result: dict) -> tuple[str, str]:
    """Derive an overall confidence label + a one-line justification."""
    signals = 0
    reasons = []

    phone = result.get("phone") or {}
    if phone.get("valid"):
        signals += 1
        reasons.append("phone numbering metadata")
    if (phone.get("correlation") or {}).get("usernames"):
        signals += 1
        reasons.append("cross-platform username correlation")
    if result.get("breach"):
        signals += 1
        reasons.append("breach database matches")
    if result.get("username"):
        signals += 1
        reasons.append("username footprint")
    dns = result.get("dns") or {}
    if isinstance(dns, dict) and not dns.get("error"):
        signals += 1
        reasons.append("DNS/domain metadata")

    if signals >= 3:
        label = "HIGH"
    elif signals == 2:
        label = "MEDIUM"
    else:
        label = "LOW"

    note = (
        f"Confidence is {label.title()} because {len(reasons)} independent signal source(s) "
        f"({', '.join(reasons) if reasons else 'minimal data'}) were available for this target."
    )
    return label, note


def build_summary(target: str, result: dict) -> InvestigationSummary:
    summary = InvestigationSummary()
    paragraphs: list[str] = []

    phone = result.get("phone")
    if isinstance(phone, dict) and phone:
        paragraphs.extend(_phone_summary(phone))

    dns = result.get("dns")
    if isinstance(dns, dict) and dns:
        paragraphs.extend(_domain_summary(result))

    unames = result.get("username")
    if isinstance(unames, list):
        paragraphs.extend(_username_summary(unames))

    breach = result.get("breach")
    paragraphs.extend(_breach_summary(breach if isinstance(breach, list) else []))

    dark = result.get("dark") or {}
    if isinstance(dark, dict):
        if dark.get("flagged"):
            paragraphs.append("⚠ This target has been flagged by threat intelligence sources — review the Threat Monitoring section.")
        else:
            paragraphs.append("No active threat intelligence flags were found for this target.")

    if not paragraphs:
        paragraphs = ["Insufficient data was returned to generate a meaningful investigation summary."]

    label, note = _confidence_from_signals(result)

    summary.headline = f"Investigation Summary for {target}"
    summary.paragraphs = paragraphs
    summary.confidence = label
    summary.confidence_note = note
    return summary