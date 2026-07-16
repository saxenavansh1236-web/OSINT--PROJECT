"""
OCR Text Extraction — pulls readable text out of an uploaded image using
EasyOCR (a PyTorch-based OCR engine that doesn't need a system binary
like Tesseract). Useful for screenshots, signs, documents, ID cards, etc.

The reader is loaded lazily and cached at module level, since model
loading takes a few seconds — we don't want to pay that cost per request.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

_reader = None
_DEPS_OK = True
try:
    import easyocr
except ImportError:
    _DEPS_OK = False


@dataclass
class OcrLine:
    text: str
    confidence: float
    bbox: list  # 4 [x, y] corner points

    def to_dict(self):
        return {"text": self.text, "confidence": round(self.confidence, 3), "bbox": self.bbox}


@dataclass
class OcrResult:
    available: bool = True
    error: Optional[str] = None
    full_text: str = ""
    lines: list = field(default_factory=list)
    language: str = "en"

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "full_text": self.full_text,
            "lines": [l.to_dict() for l in self.lines],
            "language": self.language,
        }


def _get_reader(languages=("en",)):
    global _reader
    if _reader is None:
        # gpu=False keeps this safe on machines with no CUDA; set True if you have a GPU.
        _reader = easyocr.Reader(list(languages), gpu=False, verbose=False)
    return _reader


def extract_text(filepath: str, languages=("en",), min_confidence: float = 0.35) -> OcrResult:
    if not _DEPS_OK:
        return OcrResult(
            available=False,
            error="easyocr not installed. Run: pip install easyocr",
        )

    try:
        reader = _get_reader(languages)
        raw = reader.readtext(filepath)  # [(bbox, text, confidence), ...]

        lines = []
        text_parts = []
        for bbox, text, conf in raw:
            if conf < min_confidence:
                continue
            clean_bbox = [[int(x), int(y)] for x, y in bbox]
            lines.append(OcrLine(text=text, confidence=float(conf), bbox=clean_bbox))
            text_parts.append(text)

        return OcrResult(
            full_text="\n".join(text_parts),
            lines=lines,
            language="+".join(languages),
        )
    except Exception as e:
        return OcrResult(available=False, error=str(e))