"""
Landmark Detection — identifies famous landmarks/locations visible in a
photo (e.g. "Eiffel Tower", "Golden Gate Bridge") using Google Cloud
Vision's Landmark Detection API.

Consistent with this platform's evidentiary standards (see phone
Scam/Fraud Intelligence and the Spam API pattern in phone_lookup.py):
there is no free, reliable public landmark-recognition API, so this
module honestly reports "not available" when GOOGLE_VISION_API_KEY is
unset, rather than fabricating a plausible-looking guess. It never
downgrades to a fake heuristic result — landmark identity is not
something that can be reasonably estimated without an actual model.
"""
from __future__ import annotations
import base64
import os
from dataclasses import dataclass, field
from typing import Optional

import requests

_API_KEY = os.environ.get("GOOGLE_VISION_API_KEY", "")
_ENDPOINT = "https://vision.googleapis.com/v1/images:annotate"


@dataclass
class LandmarkHit:
    description: str
    confidence: float
    latitude: Optional[float]
    longitude: Optional[float]

    def to_dict(self):
        return {
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "latitude": self.latitude,
            "longitude": self.longitude,
        }


@dataclass
class LandmarkDetectionResult:
    available: bool = False
    source: str = "unconfigured"  # "provider" | "unconfigured" | "error"
    error: Optional[str] = None
    landmarks: list = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available,
            "source": self.source,
            "error": self.error,
            "landmarks": [l.to_dict() for l in self.landmarks],
            "note": self.note,
        }


def detect(filepath: str, timeout: int = 15) -> LandmarkDetectionResult:
    if not _API_KEY:
        return LandmarkDetectionResult(
            available=False,
            source="unconfigured",
            note=(
                "Landmark detection requires a Google Cloud Vision API key "
                "(GOOGLE_VISION_API_KEY). No free public landmark-recognition "
                "API exists, so this feature honestly reports 'not available' "
                "until configured, rather than guessing."
            ),
        )

    try:
        with open(filepath, "rb") as f:
            content = base64.b64encode(f.read()).decode("utf-8")

        payload = {
            "requests": [{
                "image": {"content": content},
                "features": [{"type": "LANDMARK_DETECTION", "maxResults": 5}],
            }]
        }

        resp = requests.post(
            f"{_ENDPOINT}?key={_API_KEY}", json=payload, timeout=timeout
        )
        resp.raise_for_status()
        data = resp.json()

        annotations = data.get("responses", [{}])[0].get("landmarkAnnotations", [])
        landmarks = []
        for ann in annotations:
            loc = None
            locations = ann.get("locations", [])
            if locations:
                loc = locations[0].get("latLng", {})

            landmarks.append(LandmarkHit(
                description=ann.get("description", "Unknown"),
                confidence=ann.get("score", 0.0),
                latitude=loc.get("latitude") if loc else None,
                longitude=loc.get("longitude") if loc else None,
            ))

        return LandmarkDetectionResult(
            available=True,
            source="provider",
            landmarks=landmarks,
            note="Results from Google Cloud Vision Landmark Detection.",
        )
    except Exception as e:
        return LandmarkDetectionResult(available=False, source="error", error=str(e))