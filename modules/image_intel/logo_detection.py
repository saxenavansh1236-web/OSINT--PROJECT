"""
modules/image_intel/logo_detection.py
Brand/logo detection. Requires a cloud vision API (Google Vision Logo
Detection, AWS Rekognition, or similar) — no reliable free local model
exists for open-set logo recognition. Honestly unconfigured until wired.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import os

_LOGO_API_KEY = os.environ.get("GOOGLE_VISION_API_KEY", "")  # shares the landmark key if using GCV


@dataclass
class LogoDetection:
    brand: str
    confidence: float

    def to_dict(self):
        return {"brand": self.brand, "confidence": round(self.confidence, 3)}


@dataclass
class LogoDetectionResult:
    available: bool = True
    error: Optional[str] = None
    detections: list = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "detections": [d.to_dict() for d in self.detections], "note": self.note,
        }


def detect(filepath: str) -> LogoDetectionResult:
    if not _LOGO_API_KEY:
        return LogoDetectionResult(
            available=False,
            error="Logo detection requires a Google Cloud Vision API key "
                  "(GOOGLE_VISION_API_KEY). No free open-set logo recognition API exists, "
                  "so this honestly reports 'not available' until configured, rather than guessing.",
        )

    # Wire up Google Cloud Vision's LOGO_DETECTION feature here once
    # GOOGLE_VISION_API_KEY is set (mirrors landmark_detection.py's pattern).
    try:
        raise NotImplementedError("Google Vision logo detection integration not yet implemented.")
    except Exception as e:
        return LogoDetectionResult(available=False, error=str(e))