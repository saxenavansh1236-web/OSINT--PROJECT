"""
modules/image_intel/license_plate_ocr.py
Reuses EasyOCR (already a dependency for OCR text extraction) but filters
results to plate-shaped text: short alphanumeric strings, high confidence,
roughly landscape-oriented bounding boxes.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import re

try:
    import easyocr
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False

_reader = None
_PLATE_PATTERN = re.compile(r"^[A-Z0-9\- ]{4,10}$")


@dataclass
class PlateHit:
    text: str
    confidence: float
    bbox: list

    def to_dict(self):
        return {"text": self.text, "confidence": round(self.confidence, 3), "bbox": self.bbox}


@dataclass
class LicensePlateResult:
    available: bool = True
    error: Optional[str] = None
    plates_found: list = field(default_factory=list)
    ocr_engine: str = "easyocr"
    note: str = "Heuristic filter over general OCR results — not a purpose-built ALPR model. Verify matches manually."

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "plates_found": [p.to_dict() for p in self.plates_found],
            "ocr_engine": self.ocr_engine, "note": self.note,
        }


def _get_reader():
    global _reader
    if _reader is None:
        _reader = easyocr.Reader(["en"], gpu=False, verbose=False)
    return _reader


def detect(filepath: str, min_confidence: float = 0.4) -> LicensePlateResult:
    if not _DEPS_OK:
        return LicensePlateResult(available=False, error="easyocr not installed. Run: pip install easyocr")

    try:
        reader = _get_reader()
        raw = reader.readtext(filepath)

        plates = []
        for bbox, text, conf in raw:
            if conf < min_confidence:
                continue
            cleaned = text.upper().strip()
            if not _PLATE_PATTERN.match(cleaned):
                continue
            # Skip strings that are all-digit or all-letter-only common words (weak filter)
            if cleaned.isalpha() and len(cleaned) > 6:
                continue
            xs = [p[0] for p in bbox]
            ys = [p[1] for p in bbox]
            width = max(xs) - min(xs)
            height = max(ys) - min(ys)
            if height == 0 or width / height < 1.5:  # plates are landscape-ish
                continue
            plates.append(PlateHit(
                text=cleaned, confidence=float(conf),
                bbox=[[int(x), int(y)] for x, y in bbox],
            ))

        return LicensePlateResult(plates_found=plates)
    except Exception as e:
        return LicensePlateResult(available=False, error=str(e))