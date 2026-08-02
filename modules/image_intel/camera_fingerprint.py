"""
modules/image_intel/camera_fingerprint.py
Camera Sensor Fingerprinting (lightweight PRNU-style heuristic).

REAL PRNU (Photo Response Non-Uniformity) camera identification requires
a reference "fingerprint" built from 20-50+ known photos from the SAME
physical camera, then correlating a new image's noise residual against
that reference. That reference database does NOT exist here — this
module does NOT claim to identify which camera took a photo or match it
against a database of cameras.

What it DOES do (and is honest about):
  1. Extracts the noise residual (image minus a denoised version of
     itself) — the same first step real PRNU analysis uses.
  2. Measures whether that noise pattern is spatially UNIFORM across the
     image (consistent with a single, unedited capture) or shows sharp
     regional inconsistencies (a signal — not proof — of localized
     editing/splicing, consistent with tampering detection literature).
  3. Reports "Device Consistency" as internal self-consistency of THIS
     image only — never a cross-image or cross-device match claim.

Every field that could be misread as "camera identified" is explicitly
labeled HEURISTIC and scoped to what was actually measured.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict

try:
    import numpy as np
    from PIL import Image
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False

try:
    import cv2
    _HAS_CV2 = True
except ImportError:
    _HAS_CV2 = False


@dataclass
class CameraFingerprintResult:
    available: bool = True
    error: Optional[str] = None
    noise_pattern_computed: bool = False
    noise_uniformity_score: float = 0.0        # 0-100, higher = more uniform/consistent
    device_consistency: str = "UNKNOWN"          # CONSISTENT / INCONSISTENT / UNKNOWN
    possible_edited_regions: List[Dict] = field(default_factory=list)
    possible_edited_image: bool = False
    fingerprint_hash: Optional[str] = None       # a hash of THIS image's noise pattern only
    note: str = ""
    limitation_note: str = (
        "This is NOT camera identification. There is no reference database of known "
        "camera sensor fingerprints to match against, so this tool cannot determine "
        "which camera (or even which camera model) took this photo, and cannot confirm "
        "two images came from the same device. It only checks whether THIS image's own "
        "noise pattern is internally consistent — a heuristic signal for localized "
        "editing, not a forensic camera match."
    )

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "noise_pattern_computed": self.noise_pattern_computed,
            "noise_uniformity_score": self.noise_uniformity_score,
            "device_consistency": self.device_consistency,
            "possible_edited_regions": self.possible_edited_regions,
            "possible_edited_image": self.possible_edited_image,
            "fingerprint_hash": self.fingerprint_hash,
            "note": self.note,
            "limitation_note": self.limitation_note,
        }


_GRID_LABELS = [
    "top-left", "top-center", "top-right",
    "middle-left", "center", "middle-right",
    "bottom-left", "bottom-center", "bottom-right",
]


def _extract_noise_residual(gray: "np.ndarray") -> "np.ndarray":
    """
    Standard first step of PRNU-style analysis: denoise the image, then
    subtract the denoised version from the original. What's left is the
    high-frequency noise — sensor noise, in a genuine single-capture photo,
    plus any noise a splice/edit introduces.
    """
    if _HAS_CV2:
        denoised = cv2.fastNlMeansDenoising(gray, h=10)
    else:
        # Fallback: simple gaussian-like box blur via numpy if cv2 missing
        from scipy import ndimage  # optional; guarded by outer try/except
        denoised = ndimage.uniform_filter(gray.astype(np.float32), size=5)
        denoised = denoised.astype(np.uint8)
    residual = gray.astype(np.float32) - denoised.astype(np.float32)
    return residual


def _block_stats(residual: "np.ndarray"):
    """Split the noise residual into a 3x3 grid and compute per-block
    variance — genuine sensor noise is roughly uniform in variance across
    a natural, unedited image; a spliced/edited region often has a
    noticeably different noise variance than its surroundings."""
    h, w = residual.shape
    gh, gw = h // 3, w // 3
    block_vars = []
    labels = []
    for i in range(3):
        for j in range(3):
            block = residual[
                i * gh:(i + 1) * gh if i < 2 else h,
                j * gw:(j + 1) * gw if j < 2 else w,
            ]
            if block.size == 0:
                continue
            block_vars.append(float(block.var()))
            labels.append(_GRID_LABELS[i * 3 + j])
    return labels, block_vars


def analyze(filepath: str) -> CameraFingerprintResult:
    if not _DEPS_OK:
        return CameraFingerprintResult(
            available=False,
            error="Pillow/numpy not installed. Run: pip install pillow numpy",
        )

    try:
        img = Image.open(filepath).convert("L")  # grayscale — noise analysis doesn't need color
        gray = np.array(img, dtype=np.uint8)

        if gray.size == 0:
            return CameraFingerprintResult(available=False, error="Empty or unreadable image.")

        try:
            residual = _extract_noise_residual(gray)
        except Exception as e:
            return CameraFingerprintResult(
                available=False,
                error=f"Noise residual extraction failed: {e}. "
                      f"{'Install opencv-python for best results.' if not _HAS_CV2 else ''}",
            )

        labels, block_vars = _block_stats(residual)
        if not block_vars:
            return CameraFingerprintResult(available=False, error="Image too small to analyze.")

        mean_var = float(np.mean(block_vars))
        std_var = float(np.std(block_vars)) or 1e-6

        # Coefficient of variation across blocks: low = uniform noise
        # (consistent with a single, unedited capture). High = some
        # region's noise behaves very differently from the rest.
        cv_score = std_var / (mean_var + 1e-6)
        uniformity_score = max(0.0, min(100.0, 100.0 - (cv_score * 100)))

        suspicious_regions = []
        for label, var in zip(labels, block_vars):
            z = (var - mean_var) / std_var
            if abs(z) > 2.0:
                suspicious_regions.append({
                    "region": label,
                    "noise_variance": round(var, 3),
                    "deviation_z_score": round(z, 2),
                })

        if uniformity_score >= 70 and not suspicious_regions:
            consistency = "CONSISTENT"
        elif uniformity_score < 40 or len(suspicious_regions) >= 2:
            consistency = "INCONSISTENT"
        else:
            consistency = "UNKNOWN"

        possible_edited = consistency == "INCONSISTENT"

        # A hash of THIS image's own noise pattern — useful only for
        # future exact-residual comparison against re-uploads of the
        # exact same file, NOT a cross-camera fingerprint database key.
        import hashlib
        residual_bytes = np.round(residual).astype(np.int8).tobytes()
        fingerprint_hash = hashlib.sha256(residual_bytes).hexdigest()[:32]

        return CameraFingerprintResult(
            noise_pattern_computed=True,
            noise_uniformity_score=round(uniformity_score, 1),
            device_consistency=consistency,
            possible_edited_regions=suspicious_regions,
            possible_edited_image=possible_edited,
            fingerprint_hash=fingerprint_hash,
            note=(
                "Noise uniformity is measured by comparing sensor-noise variance across "
                "9 image regions — genuine unedited photos usually show fairly even noise "
                "levels throughout. Low uniformity or flagged regions are a soft signal of "
                "possible localized editing (splicing, cloning, heavy retouching in one "
                "area), not confirmation. Resizing, heavy compression, or naturally flat "
                "regions (clear sky, blank walls) can also lower this score without any "
                "editing having occurred."
            ),
        )
    except Exception as e:
        return CameraFingerprintResult(available=False, error=str(e))
