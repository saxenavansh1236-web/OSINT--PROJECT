"""
Face Attributes: Age, Emotion, Mask, Glasses
------------------------------------------------
Age and emotion estimation via DeepFace (wraps pretrained models,
downloaded automatically on first use). Mask and glasses detection use a
lightweight edge-density heuristic on the eye/mouth bands of each
detected face when OpenCV is available; those two specific fields report
None (not computed) rather than a guess if OpenCV is missing.
Detection only — never used for identity matching or recognition.
"""
from dataclasses import dataclass, field
from typing import List, Dict
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
    error: str = None
    faces: List[Dict] = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return {"available": self.available, "error": self.error, "faces": self.faces, "note": self.note}


def _glasses_heuristic(gray_face: np.ndarray):
    if not _HAS_CV2 or gray_face.size == 0:
        return None
    h, w = gray_face.shape
    eye_band = gray_face[int(h * 0.25):int(h * 0.5), :]
    if eye_band.size == 0:
        return None
    edges = cv2.Canny(eye_band, 60, 150)
    edge_density = edges.mean() / 255.0
    return bool(edge_density > 0.12)


def _mask_heuristic(gray_face: np.ndarray):
    if not _HAS_CV2 or gray_face.size == 0:
        return None
    h, w = gray_face.shape
    lower_band = gray_face[int(h * 0.55):, :]
    if lower_band.size == 0:
        return None
    variance = float(lower_band.std())
    return bool(variance < 18)


def analyze(filepath: str) -> FaceAttributesResult:
    if not _HAS_DEEPFACE:
        return FaceAttributesResult(
            available=False,
            error="`deepface` is not installed. Run: pip install deepface",
        )

    try:
        analysis = DeepFace.analyze(
            img_path=filepath,
            actions=["age", "emotion"],
            enforce_detection=False,
            silent=True,
        )
        if isinstance(analysis, dict):
            analysis = [analysis]

        img_bgr = cv2.imread(filepath) if _HAS_CV2 else None

        faces = []
        for face in analysis:
            region = face.get("region", {}) or {}
            entry = {
                "age": face.get("age"),
                "dominant_emotion": face.get("dominant_emotion"),
                "emotion_scores": {k: round(float(v), 2) for k, v in (face.get("emotion") or {}).items()},
                "region": region,
                "glasses_detected": None,
                "mask_detected": None,
            }

            if img_bgr is not None and region:
                x, y, w, h = region.get("x", 0), region.get("y", 0), region.get("w", 0), region.get("h", 0)
                if w > 0 and h > 0:
                    crop = img_bgr[y:y + h, x:x + w]
                    if crop.size > 0:
                        gray_face = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
                        entry["glasses_detected"] = _glasses_heuristic(gray_face)
                        entry["mask_detected"] = _mask_heuristic(gray_face)

            faces.append(entry)

        return FaceAttributesResult(
            available=True,
            faces=faces,
            note=(
                "Age and emotion come from a pretrained DeepFace model — treat as an "
                "estimate, not a verified fact. Glasses/mask flags are a lightweight "
                "edge-density heuristic (only computed when OpenCV is available) and "
                "can misfire on unusual lighting or low-resolution crops. Detection "
                "only — no identity matching or recognition is performed."
            ),
        )
    except Exception as e:
        return FaceAttributesResult(available=False, error=str(e))