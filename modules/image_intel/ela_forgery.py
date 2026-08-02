"""
modules/image_intel/forgery_detection.py
Tampering Detection Suite:
  1. ELA (Error Level Analysis) — re-saves at known JPEG quality and diffs
     against the original to surface localized re-compression differences.
  2. Copy-Move / Clone Detection — ORB keypoint self-matching to find
     regions of the same image that are suspiciously near-identical but
     spatially distant (a hallmark of clone-stamped/copy-moved edits).
  3. JPEG Block / Compression Analysis — inspects quantization tables and
     8x8 block boundary artifacts to flag signs of double compression
     (re-saving after editing).

All three are classic, well-understood heuristics — NONE of them are
proof of tampering on their own, just signals for a trained analyst to
review. This is stated explicitly in every result.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import io

try:
    from PIL import Image, ImageChops
    import numpy as np
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False

try:
    import cv2
    _HAS_CV2 = True
except ImportError:
    _HAS_CV2 = False


# ══════════════════════════════════════════════════════════════════════
# Shared result dataclasses
# ══════════════════════════════════════════════════════════════════════

@dataclass
class SuspiciousRegion:
    region: str
    avg_error_level: float

    def to_dict(self):
        return {"region": self.region, "avg_error_level": self.avg_error_level}


@dataclass
class CopyMoveResult:
    available: bool = True
    error: Optional[str] = None
    suspicious_match_count: int = 0
    matches: List[Dict] = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "suspicious_match_count": self.suspicious_match_count,
            "matches": self.matches,
            "note": self.note,
        }


@dataclass
class JpegBlockResult:
    available: bool = True
    error: Optional[str] = None
    is_jpeg: bool = False
    quantization_tables_found: int = 0
    double_compression_suspected: bool = False
    blockiness_score: float = 0.0
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "is_jpeg": self.is_jpeg,
            "quantization_tables_found": self.quantization_tables_found,
            "double_compression_suspected": self.double_compression_suspected,
            "blockiness_score": self.blockiness_score,
            "note": self.note,
        }


@dataclass
class ForgeryResult:
    available: bool = True
    error: Optional[str] = None
    mean_ela: float = 0.0
    max_ela: float = 0.0
    forgery_likelihood: str = "LOW"
    suspicious_regions: List[SuspiciousRegion] = field(default_factory=list)
    copy_move: Optional[Dict] = None
    jpeg_analysis: Optional[Dict] = None
    note: str = ""

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "mean_ela": self.mean_ela,
            "max_ela": self.max_ela,
            "forgery_likelihood": self.forgery_likelihood,
            "suspicious_regions": [r.to_dict() for r in self.suspicious_regions],
            "copy_move": self.copy_move,
            "jpeg_analysis": self.jpeg_analysis,
            "note": self.note,
        }


_GRID_LABELS = [
    "top-left", "top-center", "top-right",
    "middle-left", "center", "middle-right",
    "bottom-left", "bottom-center", "bottom-right",
]


# ══════════════════════════════════════════════════════════════════════
# 1. ELA
# ══════════════════════════════════════════════════════════════════════

def _run_ela(filepath: str, jpeg_quality: int = 90):
    original = Image.open(filepath).convert("RGB")

    buf = io.BytesIO()
    original.save(buf, "JPEG", quality=jpeg_quality)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")

    diff = ImageChops.difference(original, resaved)
    diff_arr = np.array(diff, dtype=np.float32)
    error_level = diff_arr.mean(axis=2)

    mean_ela = round(float(error_level.mean()), 3)
    max_ela = round(float(error_level.max()), 3)

    h, w = error_level.shape
    gh, gw = h // 3, w // 3
    suspicious = []
    overall_std = error_level.std() or 1.0
    for i in range(3):
        for j in range(3):
            region = error_level[
                i * gh:(i + 1) * gh if i < 2 else h,
                j * gw:(j + 1) * gw if j < 2 else w,
            ]
            if region.size == 0:
                continue
            region_mean = float(region.mean())
            z = (region_mean - mean_ela) / overall_std
            if z > 2.0:
                suspicious.append(SuspiciousRegion(
                    region=_GRID_LABELS[i * 3 + j],
                    avg_error_level=round(region_mean, 3),
                ))

    return mean_ela, max_ela, suspicious


# ══════════════════════════════════════════════════════════════════════
# 2. Copy-Move / Clone Detection (ORB self-matching)
# ══════════════════════════════════════════════════════════════════════

def detect_copy_move(
    filepath: str,
    min_distance_px: int = 40,
    max_matches_to_report: int = 25,
) -> CopyMoveResult:
    """
    Detects duplicated regions within the SAME image using ORB keypoints.
    Logic: extract ORB features, match the descriptor set against itself,
    then keep only matches where (a) the descriptor distance is very low
    (near-identical patch) AND (b) the two keypoints are spatially far
    apart (min_distance_px) — because two keypoints that are simply close
    together are just normal texture repetition, not a moved region.
    """
    if not _HAS_CV2:
        return CopyMoveResult(
            available=False,
            error="opencv-python not installed. Run: pip install opencv-python",
        )

    try:
        img = cv2.imread(filepath, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return CopyMoveResult(available=False, error="Could not read image for copy-move analysis.")

        orb = cv2.ORB_create(nfeatures=2000)
        keypoints, descriptors = orb.detectAndCompute(img, None)

        if descriptors is None or len(keypoints) < 10:
            return CopyMoveResult(
                suspicious_match_count=0,
                matches=[],
                note="Not enough distinct keypoints found to run copy-move analysis "
                     "(common on very flat/low-texture images).",
            )

        bf = cv2.BFMatcher(cv2.NORM_HAMMING)
        raw_matches = bf.knnMatch(descriptors, descriptors, k=3)

        seen_pairs = set()
        candidates = []

        for match_group in raw_matches:
            for m in match_group:
                if m.queryIdx == m.trainIdx:
                    continue  # a keypoint matching itself — skip
                if m.distance > 35:
                    continue  # too dissimilar to be a copy

                pt1 = keypoints[m.queryIdx].pt
                pt2 = keypoints[m.trainIdx].pt
                spatial_dist = ((pt1[0] - pt2[0]) ** 2 + (pt1[1] - pt2[1]) ** 2) ** 0.5

                if spatial_dist < min_distance_px:
                    continue  # too close together — normal local texture, not a moved region

                pair_key = tuple(sorted([m.queryIdx, m.trainIdx]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                candidates.append({
                    "point_a": [round(pt1[0], 1), round(pt1[1], 1)],
                    "point_b": [round(pt2[0], 1), round(pt2[1], 1)],
                    "descriptor_distance": round(float(m.distance), 2),
                    "spatial_distance_px": round(spatial_dist, 1),
                })

        candidates.sort(key=lambda c: c["descriptor_distance"])
        top_candidates = candidates[:max_matches_to_report]

        return CopyMoveResult(
            suspicious_match_count=len(candidates),
            matches=top_candidates,
            note=(
                "ORB keypoint self-matching flags regions of the image that are "
                "near-identical but spatially distant — a pattern consistent with "
                "clone-stamp/copy-move editing. False positives are common on images "
                "with genuinely repetitive patterns (bricks, tiles, foliage, fences); "
                "results should be visually reviewed, not treated as confirmed edits."
            ),
        )
    except Exception as e:
        return CopyMoveResult(available=False, error=str(e))


# ══════════════════════════════════════════════════════════════════════
# 3. JPEG Block / Quantization / Double-Compression Analysis
# ══════════════════════════════════════════════════════════════════════

def analyze_jpeg_blocks(filepath: str) -> JpegBlockResult:
    """
    Inspects JPEG quantization tables (via Pillow) and measures blockiness
    at 8x8 grid boundaries (via a simple gradient-discontinuity heuristic).
    Multiple/unusual quantization tables or high blockiness that doesn't
    align with a single consistent compression pass can indicate the image
    was compressed more than once (i.e. edited and re-saved).
    """
    if not _DEPS_OK:
        return JpegBlockResult(available=False, error="Pillow/numpy not installed. Run: pip install pillow numpy")

    try:
        img = Image.open(filepath)
        is_jpeg = img.format == "JPEG"

        if not is_jpeg:
            return JpegBlockResult(
                available=True,
                is_jpeg=False,
                note="This file is not a JPEG — quantization/block analysis only applies "
                     "to JPEG-compressed images and was skipped.",
            )

        quant_tables = getattr(img, "quantization", {}) or {}
        num_tables = len(quant_tables)

        # A single fresh JPEG save typically has 2 quantization tables
        # (luminance + chrominance). More than that, or tables with unusual
        # non-monotonic scaling, can be a signal of prior re-compression —
        # though many cameras/editors legitimately produce more, so this is
        # a soft signal only.
        unusual_table_count = num_tables > 2

        gray = np.array(img.convert("L"), dtype=np.float32)
        h, w = gray.shape

        # Measure gradient discontinuity specifically AT 8x8 block boundaries
        # vs. just inside them — genuine single-compression JPEGs show a
        # measurable periodic "blockiness" at these exact boundaries.
        boundary_diffs = []
        interior_diffs = []
        for y in range(8, h - 1, 8):
            row_diff = np.abs(gray[y, :] - gray[y - 1, :]).mean()
            boundary_diffs.append(row_diff)
        for y in range(4, h - 1, 8):
            row_diff = np.abs(gray[y, :] - gray[y - 1, :]).mean()
            interior_diffs.append(row_diff)

        boundary_score = float(np.mean(boundary_diffs)) if boundary_diffs else 0.0
        interior_score = float(np.mean(interior_diffs)) if interior_diffs else 0.0
        blockiness_score = round(boundary_score - interior_score, 3)

        # Weak blockiness signal (near zero) on a JPEG can indicate the
        # 8x8 grid was disturbed by a second compression pass at a
        # different alignment/offset — a classic double-compression tell.
        weak_blockiness = blockiness_score < 0.5
        double_compression_suspected = unusual_table_count or weak_blockiness

        return JpegBlockResult(
            is_jpeg=True,
            quantization_tables_found=num_tables,
            double_compression_suspected=double_compression_suspected,
            blockiness_score=blockiness_score,
            note=(
                "Quantization table count and 8x8 block-boundary blockiness are soft "
                "signals for re-compression, not proof — resizing, cropping, or simply "
                "re-saving at high quality can also alter these values. Flagged here as "
                "'suspected' for manual review only."
            ),
        )
    except Exception as e:
        return JpegBlockResult(available=False, error=str(e))


# ══════════════════════════════════════════════════════════════════════
# Combined entry point (this is what app.py calls)
# ══════════════════════════════════════════════════════════════════════

def analyze(filepath: str, jpeg_quality: int = 90) -> ForgeryResult:
    if not _DEPS_OK:
        return ForgeryResult(available=False, error="Pillow/numpy not installed. Run: pip install pillow numpy")

    try:
        mean_ela, max_ela, suspicious = _run_ela(filepath, jpeg_quality)

        copy_move_result = detect_copy_move(filepath)
        jpeg_result = analyze_jpeg_blocks(filepath)

        # Combine signals into one overall likelihood rating
        signal_score = 0
        if len(suspicious) >= 3 or max_ela > 60:
            signal_score += 2
        elif len(suspicious) >= 1 or max_ela > 30:
            signal_score += 1

        if copy_move_result.available and copy_move_result.suspicious_match_count >= 5:
            signal_score += 2
        elif copy_move_result.available and copy_move_result.suspicious_match_count >= 1:
            signal_score += 1

        if jpeg_result.available and jpeg_result.double_compression_suspected:
            signal_score += 1

        if signal_score >= 4:
            likelihood = "HIGH"
        elif signal_score >= 2:
            likelihood = "MEDIUM"
        else:
            likelihood = "LOW"

        return ForgeryResult(
            mean_ela=mean_ela,
            max_ela=max_ela,
            forgery_likelihood=likelihood,
            suspicious_regions=suspicious,
            copy_move=copy_move_result.to_dict(),
            jpeg_analysis=jpeg_result.to_dict(),
            note=(
                "This is a combined heuristic score across ELA, copy-move keypoint "
                "matching, and JPEG compression analysis — none of these individually "
                "or combined constitute proof of tampering. Heavily re-compressed or "
                "resized images naturally show more uniform error levels and can trigger "
                "false positives; results should be interpreted by a trained analyst."
            ),
        )
    except Exception as e:
        return ForgeryResult(available=False, error=str(e))
