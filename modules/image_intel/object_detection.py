"""
Object Detection — runs YOLOv11 (nano weights, ~5MB, auto-downloaded on
first use) over the uploaded image to identify objects present (person,
car, phone, weapon-adjacent items, laptop, backpack, etc.), which is
useful OSINT context (e.g. "this photo was taken in an office" / "a
firearm is visible" / "multiple people present").

The model is loaded lazily and cached at module level.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

_model = None
_DEPS_OK = True
try:
    from ultralytics import YOLO
except ImportError:
    _DEPS_OK = False

# Categories worth flagging distinctly for investigative context
_SENSITIVE_CLASSES = {"knife", "gun", "scissors", "person"}


@dataclass
class DetectedObject:
    label: str
    confidence: float
    box: dict  # {x1, y1, x2, y2}
    sensitive: bool

    def to_dict(self):
        return {
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "box": self.box,
            "sensitive": self.sensitive,
        }


@dataclass
class ObjectDetectionResult:
    available: bool = True
    error: Optional[str] = None
    total_found: int = 0
    objects: list = field(default_factory=list)
    label_counts: dict = field(default_factory=dict)
    person_count: int = 0

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "total_found": self.total_found,
            "objects": [o.to_dict() for o in self.objects],
            "label_counts": self.label_counts,
            "person_count": self.person_count,
        }


def _get_model():
    global _model
    if _model is None:
        # yolo11n.pt = nano variant: fast, small, CPU-friendly. Downloads once, then cached.
        _model = YOLO("yolo11n.pt")
    return _model


def detect(filepath: str, confidence_threshold: float = 0.35) -> ObjectDetectionResult:
    if not _DEPS_OK:
        return ObjectDetectionResult(
            available=False,
            error="ultralytics not installed. Run: pip install ultralytics",
        )

    try:
        model = _get_model()
        results = model.predict(filepath, conf=confidence_threshold, verbose=False)

        objects = []
        label_counts: dict = {}
        for r in results:
            names = r.names
            for box in r.boxes:
                cls_id = int(box.cls[0])
                label = names.get(cls_id, str(cls_id))
                conf = float(box.conf[0])
                x1, y1, x2, y2 = [float(v) for v in box.xyxy[0]]

                objects.append(DetectedObject(
                    label=label, confidence=conf,
                    box={"x1": round(x1), "y1": round(y1), "x2": round(x2), "y2": round(y2)},
                    sensitive=label.lower() in _SENSITIVE_CLASSES,
                ))
                label_counts[label] = label_counts.get(label, 0) + 1

        objects.sort(key=lambda o: o.confidence, reverse=True)

        return ObjectDetectionResult(
            total_found=len(objects),
            objects=objects,
            label_counts=label_counts,
            person_count=label_counts.get("person", 0),
        )
    except Exception as e:
        return ObjectDetectionResult(available=False, error=str(e))