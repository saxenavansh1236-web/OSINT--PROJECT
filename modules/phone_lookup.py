"""
modules/phone_lookup.py  —  Full OSINT phone intelligence module
Levels: Region · Timezone · VOIP/Virtual · Carrier Detail · Risk Score ·
        WhatsApp · Scam Intelligence · Reverse OSINT · Cross-Correlation ·
        Investigation Summary · Number-Type Deep Dive · Porting Disclosure
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
HLR_API_KEY  = os.environ.get("HLR_API_KEY", "")
BUSINESS_DIRECTORY_API_KEY = os.environ.get("BUSINESS_DIRECTORY_API_KEY", "")

_VOIP_CARRIER_HINTS = [
    "voip", "twilio", "bandwidth", "vonage", "skype", "google voice",
    "textnow", "textfree", "pinger", "bandwidth.com", "level 3",
    "onvoy", "telnyx", "plivo", "sinch", "flowroute", "peerless",
    "vopium", "nextiva", "ringcentral", "grasshopper", "ooma",
]

_DISPOSABLE_HINTS = [
    "textnow", "textfree", "pinger", "google voice", "burner",
    "hushed", "sideline", "2ndline",
]

# Human-readable labels for phonenumbers' full PhoneNumberType enum —
# previously collapsed into a few buckets, now exposed in full so an
# investigator can see the raw classification, not just mobile/landline/voip.
_FULL_TYPE_LABELS = {
    0: "FIXED_LINE",
    1: "MOBILE",
    2: "FIXED_LINE_OR_MOBILE",
    3: "TOLL_FREE",
    4: "PREMIUM_RATE",
    5: "SHARED_COST",
    6: "VOIP",
    7: "PERSONAL_NUMBER",
    8: "PAGER",
    9: "UAN",
    10: "UNKNOWN",
    27: "EMERGENCY",
    28: "VOICEMAIL",
    29: "SHORT_CODE",
    30: "STANDARD_RATE",
}


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
    available:         bool = False
    source:             str = "none"
    spam_reports:       Optional[int] = None
    robocall_reports:   Optional[int] = None
    fraud_score:        Optional[str] = None
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
    available:   bool = False
    network:     Optional[str] = None
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
    available: bool = False
    name:      Optional[str] = None
    type:      Optional[str] = None
    source:    Optional[str] = None
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
    label:    str
    platform: str
    url:      str
    category: str = "Reverse Lookup"

    def to_dict(self) -> dict:
        return {"label": self.label, "platform": self.platform,
                "url": self.url, "category": self.category}


@dataclass
class NumberValidityDetail:
    """
    Deep validity breakdown — distinguishes 'possible' (correct length/
    format for its region) from 'valid' (passes the full carrier-range
    validation). A number can be possible-but-invalid, which is itself
    a useful fraud/typo signal.
    """
    is_possible:      bool = False
    is_valid:         bool = False
    possible_reason:  str = ""   # phonenumbers' ValidationResult name
    raw_type:         str = "UNKNOWN"   # full enum label, e.g. "FIXED_LINE_OR_MOBILE"
    note:             str = ""

    def to_dict(self) -> dict:
        return {
            "is_possible": self.is_possible,
            "is_valid": self.is_valid,
            "possible_reason": self.possible_reason,
            "raw_type": self.raw_type,
            "note": self.note,
        }


@dataclass
class NumberPatternFlags:
    """
    Local, zero-dependency pattern heuristics — sequential digits,
    repeated-digit runs, and known India telemarketing/toll-free prefix
    ranges. Never presented as proof of anything, only as a contributing
    signal alongside everything else.
    """
    is_sequential:      bool = False
    is_repeated_digit:  bool = False
    is_telemarketing_range: bool = False
    matched_prefix:     Optional[str] = None
    flags:              list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_sequential": self.is_sequential,
            "is_repeated_digit": self.is_repeated_digit,
            "is_telemarketing_range": self.is_telemarketing_range,
            "matched_prefix": self.matched_prefix,
            "flags": self.flags,
        }


@dataclass
class InvestigationSummary:
    paragraphs:      list[str] = field(default_factory=list)
    key_findings:    list[str] = field(default_factory=list)
    confidence:      str = "LOW"
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
    rfc3966:        str = ""
    country_code:   str = ""
    country_name:   str = ""
    carrier_name:   str = ""
    line_type:      str = "unknown"

    is_mobile:      bool = False
    is_voip:        bool = False
    is_virtual:     bool = False
    is_disposable:  bool = False
    voip_matched_hint: Optional[str] = None

    region:         str = ""
    timezones:      list[str] = field(default_factory=list)

    validity_detail:    Optional[NumberValidityDetail] = None
    pattern_flags:      Optional[NumberPatternFlags] = None
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
        if not self.valid:
            return {"available": False, "note": "Cannot assess VOIP status for an invalid number."}
        if not self.carrier_name and self.line_type == "unknown":
            return {
                "available": True, "is_voip": False, "confidence": "none",
                "note": "No carrier name or line type resolved; cannot assess VOIP status.",
            }

        confidence = "medium" if self.voip_matched_hint else "low"
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
            "available": True, "is_voip": is_flagged, "confidence": confidence,
            "matched_provider": self.voip_matched_hint, "note": note,
        }

    def _porting_view(self) -> dict:
        cd = self.carrier_detail
        if not cd:
            return {"available": False, "note": "Porting history unavailable."}
        if not cd.available:
            return {
                "available": False,
                "note": cd.note + " Note: even when unavailable, treat the carrier "
                        "name above as a snapshot — Mobile Number Portability (MNP) "
                        "means the original issuing carrier and the number's current "
                        "network operator can differ without a live HLR check.",
            }
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
            "rfc3966": self.rfc3966,
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
            "validity_detail": self.validity_detail.to_dict() if self.validity_detail else None,
            "pattern_flags": self.pattern_flags.to_dict() if self.pattern_flags else None,
            "risk": self.risk.to_dict() if self.risk else None,
            "whatsapp": self.whatsapp.to_dict() if self.whatsapp else None,
            "scam": self.scam.to_dict() if self.scam else None,
            "carrier_detail": self.carrier_detail.to_dict() if self.carrier_detail else None,
            "business": self.business.to_dict() if self.business else None,
            "correlation": self.correlation.to_dict() if self.correlation else None,
            "public_mentions": [m.to_dict() for m in self.public_mentions],
            "summary": self.summary.to_dict() if self.summary else None,
            "voip": self._voip_view(),
            "porting": self._porting_view(),
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "error": self.error,
        }


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def _get_region(parsed) -> str:
    if not _HAS_PHONENUMBERS:
        return ""
    try:
        return geocoder.description_for_number(parsed, "en") or ""
    except Exception:
        return ""


def _get_timezones(parsed) -> list[str]:
    if not _HAS_PHONENUMBERS:
        return []
    try:
        tzs = pn_timezone.time_zones_for_number(parsed)
        return list(tzs) if tzs else []
    except Exception:
        return []


def _detect_voip_flags(carrier_name: str, line_type: str) -> tuple[bool, bool, bool, Optional[str]]:
    name_lower = (carrier_name or "").lower()
    matched_hint = next((h for h in _VOIP_CARRIER_HINTS if h in name_lower), None)
    is_voip = line_type == "voip" or matched_hint is not None
    is_virtual = is_voip
    is_disposable = any(h in name_lower for h in _DISPOSABLE_HINTS)
    return is_voip, is_virtual, is_disposable, matched_hint


def _build_validity_detail(parsed, raw_target: str) -> NumberValidityDetail:
    """
    Possible-vs-valid distinction: a number can be the right length/shape
    for its region (possible) yet fail carrier-range validation (invalid).
    That gap is itself a signal — e.g. common in typo'd or fabricated
    numbers used in fraud/scam contexts.
    """
    detail = NumberValidityDetail()
    if not _HAS_PHONENUMBERS:
        return detail

    try:
        detail.is_valid = phonenumbers.is_valid_number(parsed)
    except Exception:
        detail.is_valid = False

    try:
        possible_result = phonenumbers.is_possible_number_with_reason(parsed)
        # ValidationResult enum: IS_POSSIBLE=0, INVALID_COUNTRY_CODE=1,
        # TOO_SHORT=2, TOO_LONG=3, INVALID_LENGTH=5
        reason_map = {
            0: "IS_POSSIBLE",
            1: "INVALID_COUNTRY_CODE",
            2: "TOO_SHORT",
            3: "TOO_LONG",
            4: "IS_POSSIBLE_LOCAL_ONLY",
            5: "INVALID_LENGTH",
        }
        detail.possible_reason = reason_map.get(int(possible_result), "UNKNOWN")
        detail.is_possible = int(possible_result) == 0
    except Exception:
        detail.is_possible = phonenumbers.is_possible_number(parsed) if _HAS_PHONENUMBERS else False
        detail.possible_reason = "IS_POSSIBLE" if detail.is_possible else "UNKNOWN"

    try:
        raw_type_int = int(phonenumbers.number_type(parsed))
        detail.raw_type = _FULL_TYPE_LABELS.get(raw_type_int, f"TYPE_{raw_type_int}")
    except Exception:
        detail.raw_type = "UNKNOWN"

    if detail.is_possible and not detail.is_valid:
        detail.note = (
            "Number has the correct length/format for its region but does not "
            "match any assigned carrier range — possibly a typo, unassigned "
            "number, or fabricated number."
        )
    elif not detail.is_possible:
        detail.note = f"Number fails basic format checks ({detail.possible_reason})."
    else:
        detail.note = "Number passes both possibility and full validity checks."

    return detail


def _build_pattern_flags(national_digits: str, country_code: str) -> NumberPatternFlags:
    """
    Zero-dependency local heuristics on the digit string itself.
    India-specific telemarketing/service prefixes are checked only when
    country_code == '91'; otherwise only generic sequential/repeated
    checks run. Always a supporting signal, never a standalone verdict.
    """
    flags = NumberPatternFlags()
    digits = re.sub(r"\D", "", national_digits or "")
    if len(digits) < 6:
        return flags

    # Sequential ascending or descending run of 5+ digits (e.g. 123456, 987654)
    asc = "0123456789"
    desc = asc[::-1]
    if any(digits[i:i+5] in asc for i in range(len(digits) - 4)) or \
       any(digits[i:i+5] in desc for i in range(len(digits) - 4)):
        flags.is_sequential = True
        flags.flags.append("Contains a 5+ digit sequential run")

    # Same digit repeated 5+ times in a row (e.g. 999999xxxx)
    for d in "0123456789":
        if d * 5 in digits:
            flags.is_repeated_digit = True
            flags.flags.append(f"Contains 5+ repeated '{d}' digits in a row")
            break

    if country_code == "91":
        # Common India telemarketing / commercial-service prefixes
        india_prefixes = {
            "140": "Telemarketing (TRAI-designated commercial communication prefix)",
            "1600": "Toll-free customer service",
            "1800": "Toll-free customer service",
        }
        for prefix, meaning in india_prefixes.items():
            if digits.startswith(prefix):
                flags.is_telemarketing_range = True
                flags.matched_prefix = prefix
                flags.flags.append(meaning)
                break

    if not flags.flags:
        flags.flags.append("No pattern anomalies detected")

    return flags


# ══════════════════════════════════════════════════════════════
# RISK SCORING
# ══════════════════════════════════════════════════════════════

def _calculate_risk(result: PhoneResult) -> PhoneRisk:
    score = 0
    reasons = []

    if result.valid:
        score += 25
        reasons.append("✓ Valid number")
    else:
        reasons.append("✗ Invalid number")

    vd = result.validity_detail
    if vd and vd.is_possible and not vd.is_valid:
        score = max(score - 10, 0)
        reasons.append("⚠ Number is format-possible but fails carrier-range validation")

    if result.line_type == "mobile":
        score += 22
        reasons.append("✓ Mobile number")
    elif result.line_type == "landline":
        score += 15
        reasons.append("✓ Landline number")
    elif result.line_type == "voip":
        score += 5
        reasons.append("⚠ VoIP number (lower trust)")
    elif result.line_type == "toll_free":
        reasons.append("ℹ Toll-free number")
    elif result.line_type == "premium":
        score = max(score - 10, 0)
        reasons.append("⚠ Premium-rate number (common in scam schemes)")
    else:
        reasons.append("✗ Unknown line type")

    if result.is_disposable:
        reasons.append("⚠ Signals match a known disposable/virtual-number service")
    elif result.is_voip:
        reasons.append("⚠ Signals match a known VOIP provider")

    pf = result.pattern_flags
    if pf:
        if pf.is_sequential:
            score = max(score - 8, 0)
            reasons.append("⚠ Sequential digit pattern detected")
        if pf.is_repeated_digit:
            score = max(score - 5, 0)
            reasons.append("⚠ Repeated-digit pattern detected")
        if pf.is_telemarketing_range:
            score = max(score - 5, 0)
            reasons.append(f"⚠ Matches known telemarketing/service prefix ({pf.matched_prefix})")

    if result.region:
        score += 18
        reasons.append(f"✓ Region identified: {result.region}")
    else:
        reasons.append("✗ Region not identified")

    if result.carrier_name:
        score += 13
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

    score = min(max(score, 0), 100)
    level = "LOW" if score >= 70 else "MEDIUM" if score >= 40 else "HIGH"

    return PhoneRisk(level=level, score=score, reasons=reasons)


# ══════════════════════════════════════════════════════════════
# WHATSAPP PRESENCE
# ══════════════════════════════════════════════════════════════

def _check_whatsapp(e164: str) -> WhatsAppStatus:
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
# SCAM / SPAM INTELLIGENCE (now folds in pattern_flags too)
# ══════════════════════════════════════════════════════════════

def _heuristic_scam_estimate(result: PhoneResult) -> ScamReputation:
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

    if result.line_type == "premium":
        basis.append("Premium-rate number type")
        risk_points += 2

    pf = result.pattern_flags
    if pf:
        if pf.is_sequential:
            basis.append("Sequential digit pattern in number")
            risk_points += 1
        if pf.is_repeated_digit:
            basis.append("Repeated-digit pattern in number")
            risk_points += 1

    vd = result.validity_detail
    if vd and vd.is_possible and not vd.is_valid:
        basis.append("Possible-but-invalid number (fails carrier-range check)")
        risk_points += 1

    if not basis:
        basis.append("No elevated-risk signals detected in available data")

    fraud_score = "High" if risk_points >= 4 else "Medium" if risk_points >= 2 else "Low"

    return ScamReputation(
        available=True,
        source="heuristic",
        spam_reports=None,
        robocall_reports=None,
        fraud_score=fraud_score,
        fraud_score_basis=basis,
        last_reported=None,
        note=("No licensed spam-report provider configured — this is a heuristic "
              "estimate derived from carrier/validity/pattern signals only, not a "
              "verified report count. Configure SPAM_API_KEY for real figures."),
    )


def _check_scam(result: PhoneResult) -> ScamReputation:
    if not SPAM_API_KEY:
        return _heuristic_scam_estimate(result)

    try:
        estimate = _heuristic_scam_estimate(result)
        estimate.note = ("SPAM_API_KEY is set but the provider integration is not "
                          "implemented yet — showing a heuristic estimate in the "
                          "meantime. Wire in the real call in _check_scam().")
        return estimate
    except Exception as e:
        return ScamReputation(available=False, note=f"Provider error: {e}")


# ══════════════════════════════════════════════════════════════
# CARRIER DETAIL (HLR)
# ══════════════════════════════════════════════════════════════

def _check_carrier_detail(e164: str) -> CarrierDetail:
    if not HLR_API_KEY:
        return CarrierDetail()

    try:
        return CarrierDetail(
            available=False,
            note="HLR_API_KEY is set but provider integration is not implemented yet.",
        )
    except Exception as e:
        return CarrierDetail(available=False, note=f"Provider error: {e}")


# ══════════════════════════════════════════════════════════════
# BUSINESS LISTING
# ══════════════════════════════════════════════════════════════

def _check_business(e164: str) -> BusinessListing:
    if not BUSINESS_DIRECTORY_API_KEY:
        return BusinessListing()

    try:
        return BusinessListing(
            available=False,
            note="BUSINESS_DIRECTORY_API_KEY is set but provider integration is not implemented yet.",
        )
    except Exception as e:
        return BusinessListing(available=False, note=f"Provider error: {e}")


# ══════════════════════════════════════════════════════════════
# REVERSE PHONE OSINT (search-link suggestions only)
# ══════════════════════════════════════════════════════════════

def _build_public_mentions(e164: str, national: str, international: str) -> list[PublicMentionLink]:
    if not e164:
        return []

    digits = re.sub(r"[^\d]", "", e164)
    q_e164 = requests.utils.quote(e164)
    q_national = requests.utils.quote(national or e164)

    links = [
        PublicMentionLink("Reverse lookup directory", "Sync.me",
                           f"https://sync.me/search/?number={digits}", "Reverse Lookup"),
        PublicMentionLink("Reverse lookup directory", "WhoCallsMe",
                           f"https://whocallsme.com/Phone-Number.aspx/{digits}", "Reverse Lookup"),
        PublicMentionLink("Community spam reports", "ShouldIAnswer",
                           f"https://www.shouldianswer.com/phone-number/{digits}", "Reverse Lookup"),
        PublicMentionLink("General web mentions", "Google",
                           f"https://www.google.com/search?q=%22{q_e164}%22+OR+%22{q_national}%22", "General Mentions"),
        PublicMentionLink("Classifieds / marketplace mentions", "Google (site-scoped)",
                           f"https://www.google.com/search?q=%22{q_e164}%22+site:craigslist.org+OR+site:olx.com",
                           "General Mentions"),
        PublicMentionLink("Social profile search", "Facebook",
                           f"https://www.facebook.com/search/top/?q={q_e164}", "Social Profiles"),
        PublicMentionLink("Messaging profile check", "Telegram (t.me resolver)",
                           f"https://t.me/{digits}", "Social Profiles"),
    ]
    return links


# ══════════════════════════════════════════════════════════════
# CROSS-CORRELATION
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
# INVESTIGATION SUMMARY
# ══════════════════════════════════════════════════════════════

def _build_summary(result: PhoneResult) -> InvestigationSummary:
    paragraphs = []
    findings = []

    if not result.valid:
        vd = result.validity_detail
        extra = ""
        if vd and vd.is_possible:
            extra = (" The number is at least format-possible for its region, but "
                     "fails carrier-range validation — this can indicate a typo, "
                     "an unassigned number, or a fabricated number.")
        paragraphs.append(
            f"The number {result.raw!r} did not pass standard validity checks."
            + extra +
            " Most downstream signals (carrier, region, risk) are unreliable "
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

    pf = result.pattern_flags
    if pf and (pf.is_sequential or pf.is_repeated_digit or pf.is_telemarketing_range):
        bits = [f for f in [
            "a sequential digit run" if pf.is_sequential else None,
            "a repeated-digit pattern" if pf.is_repeated_digit else None,
            f"a known telemarketing/service prefix ({pf.matched_prefix})" if pf.is_telemarketing_range else None,
        ] if f]
        paragraphs.append(
            "The digit pattern itself shows " + " and ".join(bits) +
            ", which is a mild additional signal alongside the carrier/validity data — not conclusive on its own."
        )

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

    conf_score = result.confidence
    if result.correlation and result.correlation.confidence >= 40:
        conf_score = max(conf_score, result.correlation.confidence)

    confidence = "HIGH" if conf_score >= 70 else "MEDIUM" if conf_score >= 40 else "LOW"
    confidence_note = (
        "Confidence reflects how many independent signals agree (validity, carrier, "
        "region, pattern analysis, cross-correlation) — it is not a certainty score, "
        "and public phone OSINT can and does return false positives/negatives."
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
    try:
        result.rfc3966 = phonenumbers.format_number(parsed, PhoneNumberFormat.RFC3966)
    except Exception:
        result.rfc3966 = ""
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

    # ── NEW: deep validity + pattern analysis ──
    result.validity_detail = _build_validity_detail(parsed, target)
    result.pattern_flags = _build_pattern_flags(result.national, result.country_code)

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
