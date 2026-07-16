"""
modules/image_intel/vehicle_detection.py
Vehicle make/model classification. Requires a specialized fine-tuned
model (e.g. Stanford Cars-trained classifier) that isn't bundled by
default — YOLOv11 alone only gives you the generic "car" class, not
make/model. Honestly reports unavailable until such a model is wired in.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import os

_VEHICLE_MODEL_PATH = os.environ.get("VEHICLE_MODEL_PATH", "")


@dataclass
class VehiclePrediction:
    make_model: str
    confidence: float

    def to_dict(self):
        return {"make_model": self.make_model, "confidence": round(self.confidence, 3)}


@dataclass
class VehicleDetectionResult:
    available: bool = True
    error: Optional[str] = None
    top_prediction: Optional[str] = None
    confidence: float = 0.0
    predictions: list = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "top_prediction": self.top_prediction, "confidence": self.confidence,
            "predictions": [p.to_dict() for p in self.predictions], "note": self.note,
        }


def detect(filepath: str) -> VehicleDetectionResult:
    if not _VEHICLE_MODEL_PATH:
        return VehicleDetectionResult(
            available=False,
            error="Vehicle make/model detection requires a fine-tuned classifier "
                  "(set VEHICLE_MODEL_PATH to a trained weights file, e.g. one fine-tuned "
                  "on the Stanford Cars dataset). Your existing object_detection.py YOLO model "
                  "only classifies the generic 'car' class, not make/model, so this is a "
                  "separate model — not yet configured.",
        )

    # Load and run your fine-tuned classifier here once VEHICLE_MODEL_PATH is set.
    try:
        raise NotImplementedError("Vehicle classifier integration not yet implemented.")
    except Exception as e:
        return VehicleDetectionResult(available=False, error=str(e))