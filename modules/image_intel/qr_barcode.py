"""
QR / Barcode Detection — scans an image for embedded QR codes and
common 1D barcode formats (EAN, UPC, Code128, Code39, etc.) using pyzbar
(a Python binding for the zbar library).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

try:
    from pyzbar.pyzbar import decode as zbar_decode
    from PIL import Image
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False


@dataclass
class BarcodeHit:
    type: str
    data: str
    rect: dict  # {left, top, width, height}
    is_url: bool

    def to_dict(self):
        return {
            "type": self.type,
            "data": self.data,
            "rect": self.rect,
            "is_url": self.is_url,
        }


@dataclass
class BarcodeScanResult:
    available: bool = True
    error: Optional[str] = None
    total_found: int = 0
    codes: list = field(default_factory=list)

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "total_found": self.total_found,
            "codes": [c.to_dict() for c in self.codes],
        }


def scan(filepath: str) -> BarcodeScanResult:
    if not _DEPS_OK:
        return BarcodeScanResult(
            available=False,
            error="pyzbar not installed. Run: pip install pyzbar (and 'apt install libzbar0' on Linux).",
        )

    try:
        img = Image.open(filepath).convert("RGB")
        decoded = zbar_decode(img)

        codes = []
        for d in decoded:
            try:
                text = d.data.decode("utf-8", errors="replace")
            except Exception:
                text = str(d.data)

            codes.append(BarcodeHit(
                type=d.type,
                data=text,
                rect={
                    "left": d.rect.left, "top": d.rect.top,
                    "width": d.rect.width, "height": d.rect.height,
                },
                is_url=text.lower().startswith(("http://", "https://")),
            ))

        return BarcodeScanResult(total_found=len(codes), codes=codes)
    except Exception as e:
        return BarcodeScanResult(available=False, error=str(e))