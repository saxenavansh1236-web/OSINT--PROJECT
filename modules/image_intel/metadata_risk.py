"""
modules/image_intel/metadata_risk.py
Scores an image's EXIF metadata for privacy/OSINT-value risk — flags
fields that leak location, device identity, timestamps, or personal
info (owner names embedded by some camera apps, serial numbers, etc.)

Now also accepts an optional hidden_data_result (from
hidden_data_extractor.py) so hidden vendor-embedded binary segments
(e.g. OPPO/OnePlus src.image, rear.depth) factor into the overall score.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from modules.image_intel import hidden_data_extractor

# (field_name, points, label, category)
_RISK_FIELDS = [
    ("GPSLatitude",        30, "Precise GPS location embedded", "location"),
    ("GPSLongitude",       0,  "", "location"),  # paired w/ latitude, no double count
    ("GPSPosition",        30, "Precise GPS location embedded", "location"),
    ("SerialNumber",       15, "Camera/device serial number present", "device"),
    ("LensSerialNumber",   10, "Lens serial number present", "device"),
    ("OwnerName",          25, "Camera owner name embedded", "identity"),
    ("Artist",             20, "Author/artist name embedded", "identity"),
    ("CameraOwnerName",    25, "Camera owner name embedded", "identity"),
    ("UserComment",        5,  "Custom user comment present", "metadata"),
    ("Software",            5,  "Editing software disclosed", "metadata"),
    ("DateTimeOriginal",   10, "Original capture timestamp preserved", "timestamp"),
    ("CreateDate",         5,  "Creation timestamp preserved", "timestamp"),
]


@dataclass
class RiskFactor:
    field: str
    points: int
    label: str
    category: str

    def to_dict(self):
        return {"field": self.field, "points": self.points, "label": self.label, "category": self.category}


@dataclass
class MetadataRiskResult:
    available: bool = True
    error: Optional[str] = None
    score: int = 0
    level: str = "Low"
    factors: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "score": self.score,
            "level": self.level,
            "factors": [f.to_dict() for f in self.factors],
            "recommendations": self.recommendations,
        }


def _level_for_score(score: int) -> str:
    if score >= 60:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def assess(metadata: dict, hidden_data_result: dict | None = None) -> MetadataRiskResult:
    """
    hidden_data_result is the dict returned by
    hidden_data_extractor.extract_hidden_segments(). It's optional so this
    function still works if called without it (backward compatible), but
    app.py now always passes it so hidden embedded segments (e.g. a full
    secondary image hidden in an OPPO/OnePlus JPEG) are reflected in the
    score, not just standard EXIF fields.
    """
    try:
        factors = []
        seen_location = False
        total = 0

        for key, points, label, category in _RISK_FIELDS:
            if key not in metadata or not metadata.get(key):
                continue
            if category == "location":
                if seen_location:
                    continue
                seen_location = True
            if points == 0:
                continue
            factors.append(RiskFactor(field=key, points=points, label=label, category=category))
            total += points

        # ── Hidden embedded data contribution ──────────────────────────
        recs = []
        if hidden_data_result:
            contribution = hidden_data_extractor.get_risk_contribution(hidden_data_result)
            if contribution["points"] > 0:
                factors.append(
                    RiskFactor(
                        field="JSONInfo",
                        points=contribution["points"],
                        label="Hidden embedded data detected",
                        category="hidden_data",
                    )
                )
                total += contribution["points"]
                recs.append(
                    f"This file contains hidden vendor-embedded data ({contribution['reason']}). "
                    "Re-save/re-export the photo through a basic editor before sharing to strip it."
                )

        total = min(total, 100)
        level = _level_for_score(total)

        if seen_location:
            recs.append("Strip GPS tags before sharing publicly (exiftool -gps:all= file.jpg).")
        if any(f.category == "identity" for f in factors):
            recs.append("Remove Artist/OwnerName fields — they can identify the photographer/device owner.")
        if any(f.category == "device" for f in factors):
            recs.append("Serial numbers can be used to link photos to a specific physical device.")
        if not recs:
            recs.append("No high-risk identifying fields detected in this image's metadata.")

        return MetadataRiskResult(score=total, level=level, factors=factors, recommendations=recs)
    except Exception as e:
        return MetadataRiskResult(available=False, error=str(e))
