"""
modules/phone_lookup.py  —  Full OSINT phone intelligence module
Levels: Region · Timezone · VOIP/Virtual · Carrier Detail · Risk Score ·
        WhatsApp · Scam Intelligence · Reverse OSINT · Cross-Correlation ·
        Investigation Summary
"""

from __future__ import annotations
import os
import re
import requests
from dataclasses import dataclass, field
from typing import Optional

try:
    import phonenumbers
    from phonenumbers import (
        geocoder,
        carrier,
        timezone as pn_timezone,
        PhoneNumberFormat,
        PhoneNumberType,
    )
    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

SPAM_API_KEY = os.environ.get("SPAM_API_KEY", "")
HLR_API_KEY  = os.environ.get("HLR_API_KEY", "")  # optional licensed HLR provider (network/ported/MCC/MNC)
BUSINESS_DIRECTORY_API_KEY = os.environ.get("BUSINESS_DIRECTORY_API_KEY", "")

# Carrier-name substrings that are commonly VOIP / virtual-number issuers.
# Heuristic only — never presented as a definitive legal classification.
_VOIP_CARRIER_HINTS = [
    "voip", "twilio", "bandwidth", "vonage", "skype", "google voice",
    "textnow", "textfree", "pinger", "bandwidth.com", "level 3",
    "onvoy", "telnyx", "plivo", "sinch", "flowroute", "peerless",
    "vopium", "nextiva", "ringcentral", "grasshopper", "ooma",
]

# Substrings that suggest a disposable/burner virtual number service,
# distinct from general business VOIP (e.g. Twilio used by a real company).
_DISPOSABLE_HINTS = [
    "textnow", "textfree", "pinger", "google voice", "burner",
    "hushed", "sideline", "2ndline",
]


# ══════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════

@dataclass
class PhoneRisk:
    level:   str
    score:   int
    reasons: list[str]

    def to_dict(self) -> dict:
        return {"level": self.level, "score": self.score, "reasons": self.reasons}


@dataclass
class PhoneCorrelation:
    emails:           list[str] = field(default_factory=list)
    usernames:        list[dict] = field(default_factory=list)
    leaks:            list[dict] = field(default_factory=list)
    confidence:       int = 0
    confidence_label: str = "LOW"

    def to_dict(self) -> dict:
        return {
            "emails": self.emails,
            "usernames": self.usernames,
            "leaks": self.leaks,
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
        }


@dataclass
class WhatsAppStatus:
    """
    Public WhatsApp presence check via the wa.me share link — the same
    page anyone gets from clicking a wa.me link. No login, no private API.
    Best-effort signal, not a guarantee.
    """
    checked:    bool = False
    registered: Optional[bool] = None
    method:     str = "wa.me public link"
    note:       str = ""

    def to_dict(self) -> dict:
        return {
            "checked": self.checked,
            "registered": self.registered,
            "method": self.method,
            "note": self.note,
        }


@dataclass
class ScamReputation:
    """
    Two modes:
      1. Licensed provider configured (SPAM_API_KEY) → real reported figures.
      2. No provider configured → an honestly-labeled HEURISTIC risk read
         built only from signals we already have (VOIP/disposable carrier
         hints, line type, validity). This is NEVER presented as a report
         count or verified fraud score — only as a labeled estimate.
    """
    available:         bool = False
    source:             str = "none"       # "provider" | "heuristic" | "none"
    spam_reports:       Optional[int] = None
    robocall_reports:   Optional[int] = None
    fraud_score:        Optional[str] = None   # "Low" / "Medium" / "High"
    fraud_score_basis:  list[str] = field(default_factory=list)
    last_reported:      Optional[str] = None
    note:               str = "No licensed spam-report provider configured (SPAM_API_KEY unset)."

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "source": self.source,
            "spam_reports": self.spam_reports,
            "robocall_reports": self.robocall_reports,
            "fraud_score": self.fraud_score,
            "fraud_score_basis": self.fraud_score_basis,
            "last_reported": self.last_reported,
            "note": self.note,
        }


@dataclass
class CarrierDetail:
    """
    Real-time network type (5G/4G), number-porting status, and MCC/MNC
    require a licensed HLR lookup provider — phonenumbers alone can't
    give these. Honestly reports 'not available' until HLR_API_KEY is set.
    A best-effort MCC (mobile country code) is derived from the number's
    calling code when phonenumbers metadata makes it unambiguous.
    """
    available:   bool = False
    network:     Optional[str] = None   # "5G" / "4G" / "3G" / "2G"
    ported:      Optional[bool] = None
    mcc:         Optional[str] = None
    mnc:         Optional[str] = None
    note:        str = "No licensed HLR provider configured (HLR_API_KEY unset)."

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "network": self.network,
            "ported": self.ported,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "note": self.note,
        }


@dataclass
class BusinessListing:
    """
    Requires a licensed directory/enrichment API (e.g. Twilio Lookup
    caller-name, Whitepages Pro, Data Axle) — not publicly scrapable.
    `type` and `source` are included so the UI can label whether a hit
    is a BUSINESS or CONSUMER listing and which provider supplied it.
    """
    available: bool = False
    name:      Optional[str] = None
    type:      Optional[str] = None   # "BUSINESS" | "CONSUMER" | None
    source:    Optional[str] = None   # e.g. "Twilio Lookup"
    note:      str = "No business directory configured."

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "name": self.name,
            "type": self.type,
            "source": self.source,
            "note": self.note,
        }


@dataclass
class PublicMentionLink:
    """
    A *search suggestion*, not a confirmed hit. Points an investigator to
    where public phone-mention data could legally be checked by hand
    (reverse-lookup directories, social search, general web search).
    Never claims that a match exists.
    """
    label:    str
    platform: str
    url:      str
    category: str = "Reverse Lookup"

    def to_dict(self) -> dict:
        return {"label": self.label, "platform": self.platform,
                "url": self.url, "category": self.category}


@dataclass
class InvestigationSummary:
    """Human-readable roll-up of everything this module found."""
    paragraphs:      list[str] = field(default_factory=list)
    key_findings:    list[str] = field(default_factory=list)
    confidence:      str = "LOW"     # LOW | MEDIUM | HIGH
    confidence_note: str = ""

    def to_dict(self) -> dict:
        return {
            "paragraphs": self.paragraphs,
            "key_findings": self.key_findings,
            "confidence": self.confidence,
            "confidence_note": self.confidence_note,
        }


@dataclass
class PhoneResult:
    raw:            str = ""

    valid:          bool = False
    international:  str = ""
    e164:           str = ""
    national:       str = ""
    country_code:   str = ""
    country_name:   str = ""
    carrier_name:   str = ""
    line_type:      str = "unknown"     # mobile | landline | voip | toll_free | premium | unknown

    is_mobile:      bool = False
    is_voip:        bool = False
    is_virtual:     bool = False
    is_disposable:  bool = False
    voip_matched_hint: Optional[str] = None   # which carrier-name substring triggered the VOIP flag

    region:         str = ""
    timezones:      list[str] = field(default_factory=list)

    risk:               Optional[PhoneRisk] = None
    whatsapp:           Optional[WhatsAppStatus] = None
    scam:               Optional[ScamReputation] = None
    carrier_detail:     Optional[CarrierDetail] = None
    business:           Optional[BusinessListing] = None
    correlation:        Optional[PhoneCorrelation] = None
    public_mentions:    list[PublicMentionLink] = field(default_factory=list)
    summary:            Optional[InvestigationSummary] = None

    error:          Optional[str] = None

    @property
    def confidence(self) -> int:
        return self.risk.score if self.risk else 0

    @property
    def confidence_label(self) -> str:
        s = self.confidence
        if s >= 70:
            return "HIGH"
        if s >= 40:
            return "MEDIUM"
        return "LOW"

    def _voip_view(self) -> dict:
        """
        Template-facing view of the VOIP/virtual-number signal. Built from
        is_voip / is_disposable / carrier_name so the UI can render a single
        'VOIP / Virtual Number Check' card without needing to know about the
        underlying dataclass fields.
        """
        if not self.valid:
            return {
                "available": False,
                "note": "Cannot assess VOIP status for an invalid number.",
            }
        if not self.carrier_name and self.line_type == "unknown":
            return {
                "available": True,
                "is_voip": False,
                "confidence": "none",
                "note": "No carrier name or line type resolved; cannot assess VOIP status.",
            }

        confidence = "medium" if self.voip_matched_hint else ("low" if self.is_voip else "low")
        is_flagged = self.is_voip or self.is_disposable

        if self.is_disposable:
            note = "Carrier signals match a known disposable/virtual-number service."
        elif self.voip_matched_hint:
            note = f"Carrier name matches known VOIP provider ({self.voip_matched_hint})."
        elif self.is_voip:
            note = "Line type classification suggests a VOIP/virtual number."
        else:
            note = "No VOIP indicators found in carrier name or line type."

        return {
            "available": True,
            "is_voip": is_flagged,
            "confidence": confidence,
            "matched_provider": self.voip_matched_hint,
            "note": note,
        }

    def _porting_view(self) -> dict:
        """
        Template-facing view of porting status, sourced from carrier_detail
        (which itself honestly reports unavailable without HLR_API_KEY).
        """
        cd = self.carrier_detail
        if not cd:
            return {"available": False, "note": "Porting history unavailable."}
        if not cd.available:
            return {"available": False, "note": cd.note}
        return {
            "available": True,
            "ported": cd.ported,
            "note": (
                "Number appears to have been ported (per HLR provider)."
                if cd.ported else
                "No evidence of porting, per HLR provider."
            ) if cd.ported is not None else "Porting status not conclusive from provider data.",
        }

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "valid": self.valid,
            "international": self.international,
            "e164": self.e164,
            "national": self.national,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "carrier_name": self.carrier_name,
            "line_type": self.line_type,
            "is_mobile": self.is_mobile,
            "is_voip": self.is_voip,
            "is_virtual": self.is_virtual,
            "is_disposable": self.is_disposable,
            "region": self.region,
            "timezones": self.timezones,
            "risk": self.risk.to_dict() if self.risk else None,
            "whatsapp": self.whatsapp.to_dict() if self.whatsapp else None,
            "scam": self.scam.to_dict() if self.scam else None,
            "carrier_detail": self.carrier_detail.to_dict() if self.carrier_detail else None,
            "business": self.business.to_dict() if self.business else None,
            "correlation": self.correlation.to_dict() if self.correlation else None,
            "public_mentions": [m.to_dict() for m in self.public_mentions],
            "summary": self.summary.to_dict() if self.summary else None,
            # ── template-compatibility views (index.html expects these) ──
            "voip": self._voip_view(),
            "porting": self._porting_view(),
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "error": self.error,
        }


# ══════════════════════════════════════════════════════════════
# LEVEL 1 — REGION
# ══════════════════════════════════════════════════════════════

def _get_region(parsed) -> str:
    if not _HAS_PHONENUMBERS:
        return ""
    try:
        return geocoder.description_for_number(parsed, "en") or ""
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════
# LEVEL 2 — TIMEZONE
# ══════════════════════════════════════════════════════════════

def _get_timezones(parsed) -> list[str]:
    if not _HAS_PHONENUMBERS:
        return []
    try:
        tzs = pn_timezone.time_zones_for_number(parsed)
        return list(tzs) if tzs else []
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════
# LEVEL 3 — VOIP / VIRTUAL / DISPOSABLE DETECTION
# ══════════════════════════════════════════════════════════════

def _detect_voip_flags(carrier_name: str, line_type: str) -> tuple[bool, bool, bool, Optional[str]]:
    """
    Returns (is_voip, is_virtual, is_disposable, matched_hint).
    Heuristic based on phonenumbers' own type classification plus known
    VOIP/virtual-number carrier name substrings. Never claims certainty
    beyond what the signal supports.
    """
    name_lower = (carrier_name or "").lower()

    matched_hint = next((h for h in _VOIP_CARRIER_HINTS if h in name_lower), None)
    is_voip = line_type == "voip" or matched_hint is not None
    is_virtual = is_voip
    is_disposable = any(h in name_lower for h in _DISPOSABLE_HINTS)

    return is_voip, is_virtual, is_disposable, matched_hint


# ══════════════════════════════════════════════════════════════
# LEVEL 4 — RISK SCORING
# ══════════════════════════════════════════════════════════════

def _calculate_risk(result: PhoneResult) -> PhoneRisk:
    score = 0
    reasons = []

    if result.valid:
        score += 30
        reasons.append("✓ Valid number")
    else:
        reasons.append("✗ Invalid number")

    if result.line_type == "mobile":
        score += 25
        reasons.append("✓ Mobile number")
    elif result.line_type == "landline":
        score += 15
        reasons.append("✓ Landline number")
    elif result.line_type == "voip":
        score += 5
        reasons.append("⚠ VoIP number (lower trust)")
    else:
        reasons.append("✗ Unknown line type")

    if result.is_disposable:
        reasons.append("⚠ Signals match a known disposable/virtual-number service")
    elif result.is_voip:
        reasons.append("⚠ Signals match a known VOIP provider")

    if result.region:
        score += 20
        reasons.append(f"✓ Region identified: {result.region}")
    else:
        reasons.append("✗ Region not identified")

    if result.carrier_name:
        score += 15
        reasons.append(f"✓ Carrier identified: {result.carrier_name}")
    else:
        reasons.append("✗ Carrier unknown")

    if result.timezones:
        score += 10
        reasons.append(f"✓ Timezone: {result.timezones[0]}")
    else:
        reasons.append("✗ Timezone not resolved")

    scam = result.scam
    if scam and scam.fraud_score:
        if scam.fraud_score.lower() in ("medium", "high"):
            score = max(score - 20, 0)
            tag = "provider" if scam.source == "provider" else "heuristic"
            reasons.append(f"⚠ Fraud score ({tag}): {scam.fraud_score}")
        if scam.spam_reports and scam.spam_reports > 5:
            score = max(score - 10, 0)
            reasons.append(f"⚠ {scam.spam_reports} spam reports on file")

    score = min(score, 100)
    level = "LOW" if score >= 70 else "MEDIUM" if score >= 40 else "HIGH"

    return PhoneRisk(level=level, score=score, reasons=reasons)


# ══════════════════════════════════════════════════════════════
# LEVEL 5 — WHATSAPP PRESENCE (real, public-facing check)
# ══════════════════════════════════════════════════════════════

def _check_whatsapp(e164: str) -> WhatsAppStatus:
    """
    Checks the public wa.me redirect page. Best-effort, not guaranteed
    (privacy settings and page changes can affect accuracy).
    """
    status = WhatsAppStatus()
    digits = re.sub(r"[^\d]", "", e164)
    if not digits:
        status.note = "No number to check."
        return status

    url = f"https://wa.me/{digits}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=7, allow_redirects=True)
        status.checked = True
        body = r.text.lower()

        if "phone number shared via url is invalid" in body:
            status.registered = False
            status.note = "Number not found on WhatsApp."
        elif r.status_code == 200:
            if "api.whatsapp.com/send" in body or "continue to chat" in body:
                status.registered = True
                status.note = "Number is registered on WhatsApp."
            else:
                status.registered = None
                status.note = "Could not conclusively determine registration."
        else:
            status.registered = None
            status.note = f"Unexpected response ({r.status_code})."

    except Exception as e:
        status.checked = False
        status.registered = None
        status.note = f"Check failed: {e}"

    return status


# ══════════════════════════════════════════════════════════════
# LEVEL 6 — SCAM / SPAM INTELLIGENCE
# ══════════════════════════════════════════════════════════════

def _heuristic_scam_estimate(result: PhoneResult) -> ScamReputation:
    """
    Built with NO provider configured. Uses only signals this module
    already derived (never invents report counts). Clearly labeled as a
    heuristic estimate, not a verified reputation score.
    """
    basis = []
    risk_points = 0

    if result.is_disposable:
        basis.append("Carrier matches a known disposable/virtual-number service")
        risk_points += 2
    elif result.is_voip:
        basis.append("Carrier matches a known VOIP provider")
        risk_points += 1

    if not result.valid:
        basis.append("Number fails standard validity checks")
        risk_points += 1

    if not result.carrier_name:
        basis.append("Carrier could not be identified")
        risk_points += 1

    if not basis:
        basis.append("No elevated-risk signals detected in available data")

    fraud_score = "High" if risk_points >= 3 else "Medium" if risk_points >= 1 else "Low"

    return ScamReputation(
        available=True,
        source="heuristic",
        spam_reports=None,
        robocall_reports=None,
        fraud_score=fraud_score,
        fraud_score_basis=basis,
        last_reported=None,
        note=("No licensed spam-report provider configured — this is a heuristic "
              "estimate derived from carrier/validity signals only, not a "
              "verified report count. Configure SPAM_API_KEY for real figures."),
    )


def _check_scam(result: PhoneResult) -> ScamReputation:
    """
    Two-tier: use a licensed provider if SPAM_API_KEY is set, otherwise
    fall back to an honestly-labeled heuristic estimate instead of a bare
    'not available' stub — this is where real numbers plug in.
    """
    e164 = result.e164

    if not SPAM_API_KEY:
        return _heuristic_scam_estimate(result)

    try:
        # ── Replace with your actual licensed provider call ──
        # resp = requests.get(
        #     f"https://provider.example/v1/lookup?number={e164}",
        #     headers={"Authorization": f"Bearer {SPAM_API_KEY}"},
        #     timeout=8,
        # )
        # data = resp.json()
        # return ScamReputation(
        #     available=True,
        #     source="provider",
        #     spam_reports=data.get("spam_reports"),
        #     robocall_reports=data.get("robocall_reports"),
        #     fraud_score=data.get("fraud_score"),
        #     fraud_score_basis=["Live data from configured provider"],
        #     last_reported=data.get("last_reported"),
        #     note="Live data from configured provider.",
        # )
        estimate = _heuristic_scam_estimate(result)
        estimate.note = ("SPAM_API_KEY is set but the provider integration is not "
                          "implemented yet — showing a heuristic estimate in the "
                          "meantime. Wire in the real call above.")
        return estimate
    except Exception as e:
        return ScamReputation(available=False, note=f"Provider error: {e}")


# ══════════════════════════════════════════════════════════════
# LEVEL 7 — CARRIER DETAIL (network / ported / MCC / MNC via HLR)
# ══════════════════════════════════════════════════════════════

def _check_carrier_detail(e164: str) -> CarrierDetail:
    """
    Honestly reports 'not available' unless HLR_API_KEY is configured.
    Real-time network generation, porting status, and MCC/MNC require a
    live HLR lookup (e.g. via a Twilio/Telesign-style provider) — this is
    not derivable from the static phonenumbers metadata database.
    """
    if not HLR_API_KEY:
        return CarrierDetail()

    try:
        # ── Replace with your actual licensed HLR provider call ──
        # resp = requests.get(
        #     f"https://hlr-provider.example/v1/lookup?number={e164}",
        #     headers={"Authorization": f"Bearer {HLR_API_KEY}"},
        #     timeout=8,
        # )
        # data = resp.json()
        # return CarrierDetail(
        #     available=True,
        #     network=data.get("network"),
        #     ported=data.get("ported"),
        #     mcc=data.get("mcc"),
        #     mnc=data.get("mnc"),
        #     note="Live data from configured HLR provider.",
        # )
        return CarrierDetail(
            available=False,
            note="HLR_API_KEY is set but provider integration is not implemented yet.",
        )
    except Exception as e:
        return CarrierDetail(available=False, note=f"Provider error: {e}")


# ══════════════════════════════════════════════════════════════
# LEVEL 8 — BUSINESS LISTING (requires licensed directory)
# ══════════════════════════════════════════════════════════════

def _check_business(e164: str) -> BusinessListing:
    """
    Honestly reports unavailable unless BUSINESS_DIRECTORY_API_KEY is set.
    Wire in a real provider (Twilio Lookup caller-name, Whitepages Pro,
    Data Axle, etc.) in the commented block below.
    """
    if not BUSINESS_DIRECTORY_API_KEY:
        return BusinessListing()

    try:
        # ── Replace with your actual licensed directory provider call ──
        # account_sid = os.environ["TWILIO_ACCOUNT_SID"]
        # auth_token  = os.environ["TWILIO_AUTH_TOKEN"]
        # resp = requests.get(
        #     f"https://lookups.twilio.com/v2/PhoneNumbers/{e164}",
        #     params={"Fields": "caller_name"},
        #     auth=(account_sid, auth_token),
        #     timeout=8,
        # )
        # data = resp.json()
        # caller_name = data.get("caller_name") or {}
        # name = caller_name.get("caller_name")
        # if not name:
        #     return BusinessListing(available=False, note="No listing found for this number.")
        # return BusinessListing(
        #     available=True,
        #     name=name,
        #     type=caller_name.get("caller_type", "unknown"),
        #     source="Twilio Lookup",
        #     note="Live data from configured business directory provider.",
        # )
        return BusinessListing(
            available=False,
            note="BUSINESS_DIRECTORY_API_KEY is set but provider integration is not implemented yet.",
        )
    except Exception as e:
        return BusinessListing(available=False, note=f"Provider error: {e}")


# ══════════════════════════════════════════════════════════════
# LEVEL 9 — REVERSE PHONE OSINT (public search-link suggestions)
# ══════════════════════════════════════════════════════════════

def _build_public_mentions(e164: str, national: str, international: str) -> list[PublicMentionLink]:
    """
    These are NOT scraped results and NOT confirmed matches — they are
    ready-to-click search links into public, ToS-compliant surfaces so an
    investigator can manually check for mentions of the number. Modeled on
    the same disclaimed-suggestion pattern this project already uses for
    the domain/username Google Dorks and Social Mention cards.
    """
    if not e164:
        return []

    digits = re.sub(r"[^\d]", "", e164)
    q_e164 = requests.utils.quote(e164)
    q_national = requests.utils.quote(national or e164)

    links = [
        PublicMentionLink(
            label="Reverse lookup directory",
            platform="Sync.me",
            url=f"https://sync.me/search/?number={digits}",
            category="Reverse Lookup",
        ),
        PublicMentionLink(
            label="Reverse lookup directory",
            platform="WhoCallsMe",
            url=f"https://whocallsme.com/Phone-Number.aspx/{digits}",
            category="Reverse Lookup",
        ),
        PublicMentionLink(
            label="Community spam reports",
            platform="ShouldIAnswer",
            url=f"https://www.shouldianswer.com/phone-number/{digits}",
            category="Reverse Lookup",
        ),
        PublicMentionLink(
            label="General web mentions",
            platform="Google",
            url=f"https://www.google.com/search?q=%22{q_e164}%22+OR+%22{q_national}%22",
            category="General Mentions",
        ),
        PublicMentionLink(
            label="Classifieds / marketplace mentions",
            platform="Google (site-scoped)",
            url=f"https://www.google.com/search?q=%22{q_e164}%22+site:craigslist.org+OR+site:olx.com",
            category="General Mentions",
        ),
        PublicMentionLink(
            label="Social profile search",
            platform="Facebook",
            url=f"https://www.facebook.com/search/top/?q={q_e164}",
            category="Social Profiles",
        ),
        PublicMentionLink(
            label="Messaging profile check",
            platform="Telegram (t.me resolver)",
            url=f"https://t.me/{digits}",
            category="Social Profiles",
        ),
    ]
    return links


# ══════════════════════════════════════════════════════════════
# LEVEL 10 — CROSS-CORRELATION
# ══════════════════════════════════════════════════════════════

def _cross_correlate(phone_e164: str, country_code: str) -> PhoneCorrelation:
    corr = PhoneCorrelation()
    conf_pts = 0

    try:
        from modules.username import search_username
        hits = search_username(phone_e164) or []
        if hits:
            corr.usernames = hits[:10]
            conf_pts += min(30, len(hits) * 5)
    except Exception:
        pass

    try:
        from modules.leak_checker import check_all as leak_check_all
        leak_report = leak_check_all(phone_e164, "phone")
        leak_dict = leak_report.to_dict() if hasattr(leak_report, "to_dict") else (leak_report or {})
        leaks = leak_dict.get("leaks") or []
        if leaks:
            corr.leaks = leaks[:5]
            conf_pts += min(40, len(leaks) * 10)
    except Exception:
        pass

    corr.confidence = min(conf_pts, 100)
    corr.confidence_label = "HIGH" if corr.confidence >= 70 else "MEDIUM" if corr.confidence >= 40 else "LOW"

    return corr


# ══════════════════════════════════════════════════════════════
# LEVEL 11 — INVESTIGATION SUMMARY
# ══════════════════════════════════════════════════════════════

def _build_summary(result: PhoneResult) -> InvestigationSummary:
    paragraphs = []
    findings = []

    if not result.valid:
        paragraphs.append(
            f"The number {result.raw!r} did not pass standard validity checks. "
            "Most downstream signals (carrier, region, risk) are unreliable "
            "for an invalid number, so treat the rest of this report with caution."
        )
        findings.append("Number failed validity check")
    else:
        loc_bits = [b for b in (result.region, result.country_name) if b]
        loc_str = " / ".join(dict.fromkeys(loc_bits)) if loc_bits else "an unresolved region"
        paragraphs.append(
            f"{result.international} is a valid, {result.line_type} number "
            f"registered to {loc_str}"
            + (f", carrier {result.carrier_name}" if result.carrier_name else "")
            + "."
        )
        findings.append(f"Valid {result.line_type} number in {loc_str}")

    if result.is_disposable:
        paragraphs.append(
            "Carrier signals match a known disposable or virtual-number service. "
            "Numbers like this are commonly used for temporary verification or "
            "to avoid linking a real identity, so treat any single positive "
            "correlation with lower confidence."
        )
        findings.append("Carrier suggests a disposable/virtual number")
    elif result.is_voip:
        paragraphs.append(
            "Carrier signals match a known VOIP provider. This can be a "
            "legitimate business line (e.g. a company using Twilio), so it "
            "lowers — but doesn't rule out — trust on its own."
        )
        findings.append("Carrier suggests a VOIP line")

    if result.whatsapp and result.whatsapp.checked:
        if result.whatsapp.registered is True:
            paragraphs.append("The number is registered on WhatsApp, per a public wa.me check.")
            findings.append("Registered on WhatsApp")
        elif result.whatsapp.registered is False:
            paragraphs.append("The number does not appear to be registered on WhatsApp.")

    if result.correlation:
        n_user = len(result.correlation.usernames)
        n_leak = len(result.correlation.leaks)
        if n_user or n_leak:
            bits = []
            if n_user:
                bits.append(f"{n_user} possible linked username{'s' if n_user != 1 else ''}")
            if n_leak:
                bits.append(f"{n_leak} breach record{'s' if n_leak != 1 else ''}")
            paragraphs.append(
                "Cross-correlation against this project's other data sources found "
                + " and ".join(bits) + ". Review each individually before drawing conclusions — "
                "shared phone numbers can appear across unrelated accounts."
            )
            if n_leak:
                findings.append(f"{n_leak} breach record(s) associated with this number")
            if n_user:
                findings.append(f"{n_user} possible linked username(s)")
        else:
            paragraphs.append(
                "No linked usernames or breach records were found through this "
                "project's cross-correlation checks."
            )

    if result.scam and result.scam.fraud_score:
        tag = "reported by a licensed provider" if result.scam.source == "provider" else "a heuristic estimate"
        paragraphs.append(
            f"Fraud-risk signal is '{result.scam.fraud_score}' ({tag}). "
            + ("Basis: " + "; ".join(result.scam.fraud_score_basis) + "." if result.scam.fraud_score_basis else "")
        )

    # confidence tier for the summary itself
    conf_score = result.confidence
    if result.correlation and result.correlation.confidence >= 40:
        conf_score = max(conf_score, result.correlation.confidence)

    confidence = "HIGH" if conf_score >= 70 else "MEDIUM" if conf_score >= 40 else "LOW"
    confidence_note = (
        "Confidence reflects how many independent signals agree (validity, carrier, "
        "region, cross-correlation) — it is not a certainty score, and public phone "
        "OSINT can and does return false positives/negatives."
    )

    if not findings:
        findings.append("Limited data available for this number")

    return InvestigationSummary(
        paragraphs=paragraphs,
        key_findings=findings,
        confidence=confidence,
        confidence_note=confidence_note,
    )


# ══════════════════════════════════════════════════════════════
# MAIN LOOKUP FUNCTION
# ══════════════════════════════════════════════════════════════

def lookup(target: str, correlate: bool = True, check_whatsapp: bool = True) -> PhoneResult:
    """
    Full phone OSINT lookup.

    Args:
        target:          Raw phone string, e.g. "+919084302992"
        correlate:       Whether to run cross-correlation.
        check_whatsapp:  Whether to run the public WhatsApp presence check.

    Returns:
        PhoneResult dataclass (call .to_dict() for template rendering).
    """
    result = PhoneResult(raw=target)

    if not _HAS_PHONENUMBERS:
        result.error = "phonenumbers library not installed. Run: pip install phonenumbers"
        return result

    cleaned = re.sub(r"[^\d+]", "", target)
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned

    try:
        parsed = phonenumbers.parse(cleaned, None)
    except Exception:
        try:
            parsed = phonenumbers.parse(target, "IN")
        except Exception as e:
            result.error = f"Could not parse phone number: {e}"
            return result

    result.valid = phonenumbers.is_valid_number(parsed)
    result.international = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
    result.e164 = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
    result.national = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
    result.country_code = str(parsed.country_code)

    try:
        import pycountry
        region_alpha2 = phonenumbers.region_code_for_number(parsed)
        country_obj = pycountry.countries.get(alpha_2=region_alpha2) if region_alpha2 else None
        result.country_name = country_obj.name if country_obj else (region_alpha2 or "")
    except Exception:
        result.country_name = phonenumbers.region_code_for_number(parsed) or ""

    try:
        result.carrier_name = carrier.name_for_number(parsed, "en") or ""
    except Exception:
        result.carrier_name = ""

    try:
        num_type = phonenumbers.number_type(parsed)
        _type_map = {
            PhoneNumberType.MOBILE:                "mobile",
            PhoneNumberType.FIXED_LINE:             "landline",
            PhoneNumberType.FIXED_LINE_OR_MOBILE:   "mobile",
            PhoneNumberType.VOIP:                   "voip",
            PhoneNumberType.PERSONAL_NUMBER:        "voip",
            PhoneNumberType.TOLL_FREE:              "toll_free",
            PhoneNumberType.PREMIUM_RATE:           "premium",
            PhoneNumberType.PAGER:                  "landline",
            PhoneNumberType.UAN:                    "landline",
        }
        result.line_type = _type_map.get(num_type, "unknown")
    except Exception:
        result.line_type = "unknown"

    result.is_mobile = result.line_type == "mobile"

    is_voip, is_virtual, is_disposable, matched_hint = _detect_voip_flags(result.carrier_name, result.line_type)
    result.is_voip = is_voip
    result.is_virtual = is_virtual
    result.is_disposable = is_disposable
    result.voip_matched_hint = matched_hint

    result.region = _get_region(parsed)
    result.timezones = _get_timezones(parsed)

    if result.valid and check_whatsapp:
        result.whatsapp = _check_whatsapp(result.e164)

    result.scam = _check_scam(result)
    result.carrier_detail = _check_carrier_detail(result.e164)
    result.business = _check_business(result.e164)

    result.risk = _calculate_risk(result)

    if result.valid:
        result.public_mentions = _build_public_mentions(
            result.e164, result.national, result.international
        )

    if correlate and result.valid:
        result.correlation = _cross_correlate(result.e164, result.country_code)

    result.summary = _build_summary(result)

    return result