"""
modules/image_intel/forgery_detection.py
Error Level Analysis (ELA) forgery detection — re-saves the image at a
known JPEG quality and diffs against the original. Regions that were
edited/spliced after the last save tend to show a different error level
than the rest of the (uniformly re-compressed) image. This is a classic,
well-understood heuristic — not proof of tampering, just a signal.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import io

try:
    from PIL import Image, ImageChops
    import numpy as np
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False


@dataclass
class SuspiciousRegion:
    region: str  # coarse grid label, e.g. "top-left"
    avg_error_level: float

    def to_dict(self):
        return {"region": self.region, "avg_error_level": self.avg_error_level}


@dataclass
class ForgeryResult:
    available: bool = True
    error: Optional[str] = None
    mean_ela: float = 0.0
    max_ela: float = 0.0
    forgery_likelihood: str = "LOW"
    suspicious_regions: list = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "mean_ela": self.mean_ela, "max_ela": self.max_ela,
            "forgery_likelihood": self.forgery_likelihood,
            "suspicious_regions": [r.to_dict() for r in self.suspicious_regions],
            "note": self.note,
        }


_GRID_LABELS = [
    "top-left", "top-center", "top-right",
    "middle-left", "center", "middle-right",
    "bottom-left", "bottom-center", "bottom-right",
]


def analyze(filepath: str, jpeg_quality: int = 90) -> ForgeryResult:
    if not _DEPS_OK:
        return ForgeryResult(available=False, error="Pillow/numpy not installed. Run: pip install pillow numpy")

    try:
        original = Image.open(filepath).convert("RGB")

        buf = io.BytesIO()
        original.save(buf, "JPEG", quality=jpeg_quality)
        buf.seek(0)
        resaved = Image.open(buf).convert("RGB")

        diff = ImageChops.difference(original, resaved)
        diff_arr = np.array(diff, dtype=np.float32)
        error_level = diff_arr.mean(axis=2)  # per-pixel avg error across RGB

        mean_ela = round(float(error_level.mean()), 3)
        max_ela = round(float(error_level.max()), 3)

        # Split into 3x3 grid, flag regions whose mean error deviates
        # sharply from the image's overall mean (a splice tends to stand out)
        h, w = error_level.shape
        gh, gw = h // 3, w // 3
        suspicious = []
        overall_std = error_level.std() or 1.0
        for i in range(3):
            for j in range(3):
                region = error_level[i * gh:(i + 1) * gh if i < 2 else h,
                                      j * gw:(j + 1) * gw if j < 2 else w]
                if region.size == 0:
                    continue
                region_mean = float(region.mean())
                z = (region_mean - mean_ela) / overall_std
                if z > 2.0:  # region error level is a clear outlier
                    suspicious.append(SuspiciousRegion(
                        region=_GRID_LABELS[i * 3 + j],
                        avg_error_level=round(region_mean, 3),
                    ))

        if len(suspicious) >= 3 or max_ela > 60:
            likelihood = "HIGH"
        elif len(suspicious) >= 1 or max_ela > 30:
            likelihood = "MEDIUM"
        else:
            likelihood = "LOW"

        return ForgeryResult(
            mean_ela=mean_ela, max_ela=max_ela,
            forgery_likelihood=likelihood,
            suspicious_regions=suspicious,
            note="ELA is a heuristic signal, not proof of tampering — heavily "
                 "re-compressed or resized images naturally show more uniform error levels; "
                 "results should be interpreted by a trained analyst.",
        )
    except Exception as e:
        return ForgeryResult(available=False, error=str(e))