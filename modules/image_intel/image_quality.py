"""
modules/image_intel/image_quality.py
Real, dependency-light image quality analysis using Pillow + numpy only
(no cv2/torch required). Computes sharpness (Laplacian variance),
brightness, contrast, and noise estimate.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

try:
    from PIL import Image
    import numpy as np
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False


@dataclass
class QualityResult:
    available: bool = True
    error: Optional[str] = None
    width: int = 0
    height: int = 0
    megapixels: float = 0.0
    resolution_class: str = "unknown"
    sharpness_score: float = 0.0
    is_blurry: bool = False
    brightness: float = 0.0
    exposure: str = "normal"
    contrast: float = 0.0
    noise_estimate: float = 0.0
    overall_quality_score: int = 0
    warnings: list = field(default_factory=list)

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "width": self.width, "height": self.height,
            "megapixels": self.megapixels, "resolution_class": self.resolution_class,
            "sharpness_score": self.sharpness_score, "is_blurry": self.is_blurry,
            "brightness": self.brightness, "exposure": self.exposure,
            "contrast": self.contrast, "noise_estimate": self.noise_estimate,
            "overall_quality_score": self.overall_quality_score,
            "warnings": self.warnings,
        }


def _laplacian_variance(gray: "np.ndarray") -> float:
    # 3x3 Laplacian kernel convolution, manual (no scipy dependency)
    kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
    h, w = gray.shape
    padded = np.pad(gray, 1, mode="edge").astype(np.float32)
    out = np.zeros_like(gray, dtype=np.float32)
    for dy in range(3):
        for dx in range(3):
            k = kernel[dy, dx]
            if k != 0:
                out += k * padded[dy:dy + h, dx:dx + w]
    return float(out.var())


def _resolution_class(mp: float) -> str:
    if mp < 1:
        return "low (<1MP)"
    if mp < 5:
        return "standard (1-5MP)"
    if mp < 12:
        return "high (5-12MP)"
    return "very high (12MP+)"


def analyze(filepath: str) -> QualityResult:
    if not _DEPS_OK:
        return QualityResult(available=False, error="Pillow/numpy not installed. Run: pip install pillow numpy")

    try:
        img = Image.open(filepath).convert("RGB")
        w, h = img.size
        mp = round((w * h) / 1_000_000, 2)

        gray = np.array(img.convert("L"), dtype=np.float32)
        # Downscale large images for speed
        if gray.size > 1_500_000:
            scale = (1_500_000 / gray.size) ** 0.5
            img_small = img.resize((max(1, int(w * scale)), max(1, int(h * scale))))
            gray = np.array(img_small.convert("L"), dtype=np.float32)

        sharpness = round(_laplacian_variance(gray), 2)
        is_blurry = sharpness < 100  # empirical threshold for Laplacian variance

        brightness = round(float(gray.mean()), 2)
        if brightness < 60:
            exposure = "underexposed"
        elif brightness > 200:
            exposure = "overexposed"
        else:
            exposure = "normal"

        contrast = round(float(gray.std()), 2)

        # Rough noise estimate: high-frequency residual after simple blur
        blurred = np.copy(gray)
        blurred[1:-1, 1:-1] = (
            gray[:-2, 1:-1] + gray[2:, 1:-1] + gray[1:-1, :-2] + gray[1:-1, 2:] + gray[1:-1, 1:-1] * 4
        ) / 8
        noise_estimate = round(float(np.abs(gray - blurred).mean()), 2)

        warnings = []
        if is_blurry:
            warnings.append("Image appears blurry — low detail/sharpness detected.")
        if exposure != "normal":
            warnings.append(f"Image is {exposure}.")
        if noise_estimate > 15:
            warnings.append("High noise level detected — possibly low-light or heavily compressed.")

        # Composite 0-100 score
        score = 100
        if is_blurry:
            score -= 30
        if exposure != "normal":
            score -= 15
        if noise_estimate > 15:
            score -= 15
        if mp < 1:
            score -= 20
        score = max(0, min(100, score))

        return QualityResult(
            width=w, height=h, megapixels=mp, resolution_class=_resolution_class(mp),
            sharpness_score=sharpness, is_blurry=is_blurry,
            brightness=brightness, exposure=exposure, contrast=contrast,
            noise_estimate=noise_estimate, overall_quality_score=score, warnings=warnings,
        )
    except Exception as e:
        return QualityResult(available=False, error=str(e))