"""
modules/image_intel/ai_generated_detection.py
Detects whether an image is likely AI-generated. Honestly reports
"unavailable" without a configured detector model/API — deliberately
avoids shipping a fake/placeholder heuristic that could mislead an
investigator into false confidence either direction.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import os

_AI_DETECTOR_API_KEY = os.environ.get("AI_DETECTOR_API_KEY", "")


@dataclass
class AiGeneratedResult:
    available: bool = True
    error: Optional[str] = None
    is_ai_generated: bool = False
    confidence: float = 0.0
    label: str = "UNKNOWN"
    source: str = ""  # "model" | "heuristic"
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "is_ai_generated": self.is_ai_generated, "confidence": self.confidence,
            "label": self.label, "source": self.source, "note": self.note,
        }


def detect(filepath: str) -> AiGeneratedResult:
    if not _AI_DETECTOR_API_KEY:
        return AiGeneratedResult(
            available=False,
            error="AI_DETECTOR_API_KEY not configured. No reliable free/local model is "
                  "wired up — this honestly reports 'not available' rather than guessing, "
                  "since a wrong verdict here is worse than no verdict.",
        )

    # Wire up your chosen provider here (e.g. Hive Moderation, Sightengine,
    # or a self-hosted classifier) once AI_DETECTOR_API_KEY is set.
    try:
        raise NotImplementedError("Provider integration not yet implemented.")
    except Exception as e:
        return AiGeneratedResult(available=False, error=str(e))