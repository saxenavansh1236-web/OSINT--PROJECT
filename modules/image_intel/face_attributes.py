"""
modules/image_intel/face_attributes.py
Age / Gender / Emotion estimation via DeepFace (pretrained models,
downloaded automatically on first use). Glasses and Mask detection use a
lightweight edge-density / lower-face-variance heuristic on each detected
face crop when OpenCV is available; those two fields report None (not
computed) rather than a guess if OpenCV or the face region is missing.

Detection + attribute ESTIMATION only — never used for identity matching
or facial recognition against any database.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import numpy as np

try:
    from deepface import DeepFace
    _HAS_DEEPFACE = True
except ImportError:
    _HAS_DEEPFACE = False

try:
    import cv2
    _HAS_CV2 = True
except ImportError:
    _HAS_CV2 = False


@dataclass
class FaceAttributesResult:
    available: bool = True
    error: Optional[str] = None
    faces: List[Dict] = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "faces": self.faces,
            "note": self.note,
        }


def _glasses_heuristic(gray_face: "np.ndarray") -> Optional[bool]:
    """Edge density across the eye band — glasses frames create sharp,
    high-density edges that bare eyes/skin don't."""
    if not _HAS_CV2 or gray_face.size == 0:
        return None
    h, w = gray_face.shape
    eye_band = gray_face[int(h * 0.25):int(h * 0.5), :]
    if eye_band.size == 0:
        return None
    edges = cv2.Canny(eye_band, 60, 150)
    edge_density = edges.mean() / 255.0
    return bool(edge_density > 0.12)


def _mask_heuristic(gray_face: "np.ndarray") -> Optional[bool]:
    """Low pixel variance across the lower third of the face — a mask
    flattens texture (no visible mouth/chin detail) compared to bare skin."""
    if not _HAS_CV2 or gray_face.size == 0:
        return None
    h, w = gray_face.shape
    lower_band = gray_face[int(h * 0.55):, :]
    if lower_band.size == 0:
        return None
    variance = float(lower_band.std())
    return bool(variance < 18)


def _eye_open_heuristic(gray_face: "np.ndarray") -> Optional[bool]:
    """Rough eye-openness check via Haar eye cascade presence + vertical
    edge count in the eye band. Not a substitute for proper landmark-based
    EAR (Eye Aspect Ratio) — treat as a coarse signal only."""
    if not _HAS_CV2 or gray_face.size == 0:
        return None
    try:
        eye_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_eye.xml"
        )
        h, w = gray_face.shape
        eye_band = gray_face[int(h * 0.2):int(h * 0.55), :]
        if eye_band.size == 0:
            return None
        eyes = eye_cascade.detectMultiScale(eye_band, scaleFactor=1.1, minNeighbors=5)
        return bool(len(eyes) >= 1)
    except Exception:
        return None


def analyze(filepath: str) -> FaceAttributesResult:
    if not _HAS_DEEPFACE:
        return FaceAttributesResult(
            available=False,
            error="`deepface` is not installed. Run: pip install deepface tf-keras "
                  "(first run downloads model weights; CPU inference is slow).",
        )

    try:
        analysis = DeepFace.analyze(
            img_path=filepath,
            actions=["age", "gender", "emotion"],
            enforce_detection=False,
            silent=True,
        )
        if isinstance(analysis, dict):
            analysis = [analysis]

        img_bgr = cv2.imread(filepath) if _HAS_CV2 else None

        faces = []
        for face in analysis:
            region = face.get("region", {}) or {}

            gender_scores = face.get("gender") or {}
            if isinstance(gender_scores, dict) and gender_scores:
                dominant_gender = max(gender_scores, key=gender_scores.get)
                gender_confidence = round(float(gender_scores[dominant_gender]), 2)
            else:
                dominant_gender = face.get("dominant_gender")
                gender_confidence = None

            entry = {
                "age": face.get("age"),
                "dominant_gender": dominant_gender,
                "gender_confidence": gender_confidence,
                "dominant_emotion": face.get("dominant_emotion"),
                "emotion_scores": {
                    k: round(float(v), 2) for k, v in (face.get("emotion") or {}).items()
                },
                "region": region,
                "glasses_detected": None,
                "mask_detected": None,
                "eyes_open": None,
            }

            if img_bgr is not None and region:
                x, y, w, h = (
                    region.get("x", 0), region.get("y", 0),
                    region.get("w", 0), region.get("h", 0),
                )
                if w > 0 and h > 0:
                    crop = img_bgr[y:y + h, x:x + w]
                    if crop.size > 0:
                        gray_face = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
                        entry["glasses_detected"] = _glasses_heuristic(gray_face)
                        entry["mask_detected"] = _mask_heuristic(gray_face)
                        entry["eyes_open"] = _eye_open_heuristic(gray_face)

            faces.append(entry)

        return FaceAttributesResult(
            available=True,
            faces=faces,
            note=(
                "Age, gender, and emotion come from a pretrained DeepFace model — "
                "treat as estimates, not verified facts. Glasses/mask/eyes-open flags "
                "are lightweight heuristics (only computed when OpenCV is available) "
                "and can misfire on unusual lighting, angles, or low-resolution crops. "
                "Detection and estimation only — no identity matching or recognition "
                "is performed."
            ),
        )
    except Exception as e:
        return FaceAttributesResult(available=False, error=str(e))
