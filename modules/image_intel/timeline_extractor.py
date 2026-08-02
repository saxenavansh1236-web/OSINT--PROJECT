"""
modules/image_intel/timeline_extractor.py
Builds a simple chronological timeline from EXIF metadata already parsed
by exiftool: when the photo was taken, when it was last modified, the
camera-embedded timezone offset (if present), and the image's age relative
to today. "Shared" timestamp is intentionally NOT fabricated — most
platforms strip or rewrite EXIF on upload/download, so there is no
reliable "shared" timestamp available from image metadata alone. This is
stated honestly rather than defaulted to something misleading.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# exiftool -j returns EXIF dates as "YYYY:MM:DD HH:MM:SS" (colon in the date part)
_EXIF_DATE_FORMATS = [
    "%Y:%m:%d %H:%M:%S",
    "%Y:%m:%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]


@dataclass
class TimelineResult:
    available: bool = True
    error: Optional[str] = None
    created_at: Optional[str] = None
    modified_at: Optional[str] = None
    timezone_offset: Optional[str] = None
    age_days: Optional[int] = None
    age_human: Optional[str] = None
    created_modified_differ: Optional[bool] = None
    shared_at: Optional[str] = None
    shared_note: str = (
        "Not available — most platforms strip or rewrite EXIF timestamps on "
        "upload/download, so a reliable 'shared' date cannot be derived from "
        "image metadata alone."
    )
    events: list = field(default_factory=list)

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "timezone_offset": self.timezone_offset,
            "age_days": self.age_days,
            "age_human": self.age_human,
            "created_modified_differ": self.created_modified_differ,
            "shared_at": self.shared_at,
            "shared_note": self.shared_note,
            "events": self.events,
        }


def _parse_exif_datetime(value: str) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip()
    for fmt in _EXIF_DATE_FORMATS:
        try:
            return datetime.strptime(cleaned[:len(fmt.replace("%z", "+0000"))], fmt)
        except ValueError:
            continue
    # Fallback: try trimming any trailing subsecond/timezone junk
    try:
        base = cleaned.split("+")[0].split("-0")[0].strip()
        return datetime.strptime(base, "%Y:%m:%d %H:%M:%S")
    except Exception:
        return None


def _humanize_days(days: int) -> str:
    if days < 0:
        return "date is in the future (clock skew or edited timestamp)"
    if days == 0:
        return "today"
    if days == 1:
        return "1 day ago"
    if days < 30:
        return f"{days} days ago"
    if days < 365:
        months = days // 30
        return f"~{months} month(s) ago"
    years = days // 365
    return f"~{years} year(s) ago"


def extract(metadata: dict) -> TimelineResult:
    try:
        created_raw = (
            metadata.get("Date/Time Original")
            or metadata.get("DateTimeOriginal")
            or metadata.get("Create Date")
            or metadata.get("CreateDate")
        )
        modified_raw = (
            metadata.get("Modify Date")
            or metadata.get("ModifyDate")
            or metadata.get("File Modification Date/Time")
            or metadata.get("FileModifyDate")
        )
        tz_offset = (
            metadata.get("Offset Time Original")
            or metadata.get("OffsetTimeOriginal")
            or metadata.get("Offset Time")
            or metadata.get("OffsetTime")
        )

        created_dt = _parse_exif_datetime(created_raw) if created_raw else None
        modified_dt = _parse_exif_datetime(modified_raw) if modified_raw else None

        if not created_dt and not modified_dt:
            return TimelineResult(
                available=False,
                error="No creation or modification timestamps found in EXIF metadata.",
            )

        age_days = None
        age_human = None
        reference_dt = created_dt or modified_dt
        if reference_dt:
            delta = datetime.now() - reference_dt
            age_days = delta.days
            age_human = _humanize_days(age_days)

        differ = None
        if created_dt and modified_dt:
            differ = created_dt != modified_dt

        events = []
        if created_dt:
            events.append({
                "label": "Photo Taken",
                "timestamp": created_raw,
                "icon": "📷",
            })
        if modified_dt and differ:
            events.append({
                "label": "File Modified",
                "timestamp": modified_raw,
                "icon": "✏️",
                "note": "Modification time differs from capture time — the file "
                        "was re-saved, edited, or processed after being taken.",
            })
        elif modified_dt:
            events.append({
                "label": "File Modified",
                "timestamp": modified_raw,
                "icon": "✏️",
            })

        return TimelineResult(
            created_at=created_raw,
            modified_at=modified_raw,
            timezone_offset=tz_offset,
            age_days=age_days,
            age_human=age_human,
            created_modified_differ=differ,
            shared_at=None,
            events=events,
        )
    except Exception as e:
        return TimelineResult(available=False, error=str(e))
