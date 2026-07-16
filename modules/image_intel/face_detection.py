"""
modules/image_intel/face_attributes.py
Age/emotion/glasses/mask estimation via DeepFace (optional heavy dep).
Detection + attribute estimation only — no identity matching, consistent
with face_detection.py's boundary.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

_DEPS_OK = True
try:
    from deepface import DeepFace
except ImportError:
    _DEPS_OK = False


@dataclass
class FaceAttrs:
    age: Optional[int] = None
    dominant_emotion: Optional[str] = None
    glasses_detected: Optional[bool] = None
    mask_detected: Optional[bool] = None

    def to_dict(self):
        return {
            "age": self.age, "dominant_emotion": self.dominant_emotion,
            "glasses_detected": self.glasses_detected, "mask_detected": self.mask_detected,
        }


@dataclass
class FaceAttributesResult:
    available: bool = True
    error: Optional[str] = None
    faces: list = field(default_factory=list)
    note: str = "Attribute estimation only — no identity matching or facial recognition is performed."

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "faces": [f.to_dict() for f in self.faces], "note": self.note,
        }


def analyze(filepath: str) -> FaceAttributesResult:
    if not _DEPS_OK:
        return FaceAttributesResult(
            available=False,
            error="deepface not installed. Run: pip install deepface tf-keras "
                  "(first run downloads model weights; CPU inference is slow).",
        )

    try:
        analyses = DeepFace.analyze(
            img_path=filepath,
            actions=["age", "emotion"],
            enforce_detection=False,
            silent=True,
        )
        if isinstance(analyses, dict):
            analyses = [analyses]

        faces = []
        for a in analyses:
            faces.append(FaceAttrs(
                age=a.get("age"),
                dominant_emotion=a.get("dominant_emotion"),
                glasses_detected=None,  # DeepFace doesn't ship this out of the box
                mask_detected=None,
            ))

        return FaceAttributesResult(faces=faces)
    except Exception as e:
        return FaceAttributesResult(available=False, error=str(e))