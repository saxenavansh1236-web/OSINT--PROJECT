"""
modules/image_intel/ai_summary.py
Consolidates every Image Intelligence card into one plain-English
investigation summary — Investigation Summary, Risk, Camera, Hidden
Metadata, Objects, OCR, Recommendation. Pure logic over data the scan
already produced; no new API calls, no fabricated results, and anything
unverifiable is explicitly labeled as such (consistent with the platform's
evidentiary standard used in modules/investigation_summary.py).

Usage:
    from modules.image_intel.ai_summary import build_image_summary
    image_intel["ai_summary"] = build_image_summary(metadata, image_intel).to_dict()
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class ImageAISummary:
    available: bool = True
    error: Optional[str] = None
    headline: str = ""
    risk_level: str = "LOW"
    camera_line: str = ""
    hidden_metadata_line: str = ""
    objects_line: str = ""
    ocr_line: str = ""
    forgery_line: str = ""
    gps_line: str = ""
    recommendations: List[str] = field(default_factory=list)
    confidence: str = "LOW"
    confidence_note: str = ""

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "headline": self.headline,
            "risk_level": self.risk_level,
            "camera_line": self.camera_line,
            "hidden_metadata_line": self.hidden_metadata_line,
            "objects_line": self.objects_line,
            "ocr_line": self.ocr_line,
            "forgery_line": self.forgery_line,
            "gps_line": self.gps_line,
            "recommendations": self.recommendations,
            "confidence": self.confidence,
            "confidence_note": self.confidence_note,
        }


def _camera_line(metadata: dict) -> str:
    make = metadata.get("Make")
    model = metadata.get("Camera Model Name") or metadata.get("Model")
    date = metadata.get("Date/Time Original") or metadata.get("DateTimeOriginal")

    if not make and not model:
        return "No camera make/model information was found in this image's metadata."

    parts = []
    if make or model:
        parts.append(f"Captured on a {make or ''} {model or ''}".strip())
    if date:
        parts.append(f"on {date}")
    return " ".join(parts) + "."


def _hidden_metadata_line(image_intel: dict) -> str:
    hd = image_intel.get("hidden_data") or {}
    if not hd.get("available"):
        return "No hidden vendor-embedded data segments were applicable to this file format."
    count = hd.get("segments_found", 0)
    if count == 0:
        return "No hidden vendor-embedded data segments were detected."
    total_kb = (hd.get("total_hidden_bytes", 0) or 0) // 1024
    return (
        f"⚠ {count} hidden vendor-embedded segment(s) were found (~{total_kb} KB total) — "
        "data not visible when viewing the photo normally. Review the Hidden Embedded "
        "Data card for details."
    )


def _objects_line(image_intel: dict) -> str:
    obj = image_intel.get("objects") or {}
    if obj.get("error") or not obj.get("total_found"):
        return "No notable objects were detected in the image."
    labels = obj.get("label_counts") or {}
    top = ", ".join(f"{k} ×{v}" for k, v in list(labels.items())[:5])
    return f"{obj.get('total_found')} object(s) detected, including: {top}."


def _ocr_line(image_intel: dict) -> str:
    ocr = image_intel.get("ocr") or {}
    if ocr.get("error") or not ocr.get("full_text"):
        return "No readable text was extracted from the image."
    lines = ocr.get("lines") or []
    return f"Text was extracted from the image ({len(lines)} line(s)) — review the OCR card for full content."


def _forgery_line(image_intel: dict) -> str:
    forg = image_intel.get("forgery") or {}
    if not forg.get("available"):
        return "Forgery/tampering analysis was not available for this image."
    likelihood = forg.get("forgery_likelihood", "LOW")
    copy_move = forg.get("copy_move") or {}
    jpeg = forg.get("jpeg_analysis") or {}

    line = f"ELA-based forgery likelihood: {likelihood}."
    if copy_move.get("available") and copy_move.get("suspicious_match_count", 0) > 0:
        line += f" {copy_move.get('suspicious_match_count')} possible copy-move region match(es) found."
    if jpeg.get("available") and jpeg.get("double_compression_suspected"):
        line += " Signs of double JPEG compression were detected, which can indicate re-saving after editing."
    return line


def _gps_line(image_intel: dict) -> str:
    gps = image_intel.get("gps") or {}
    if gps.get("has_gps"):
        return f"GPS coordinates were found embedded in the image ({gps.get('latitude')}, {gps.get('longitude')})."
    return "No GPS location data was found in the image metadata."


def _derive_risk(image_intel: dict, metadata: dict) -> tuple[str, list[str]]:
    score = 0
    recs = []

    gps = image_intel.get("gps") or {}
    if gps.get("has_gps"):
        score += 30
        recs.append("Strip GPS metadata before sharing this image publicly if location privacy matters.")

    hd = image_intel.get("hidden_data") or {}
    if hd.get("available") and hd.get("segments_found", 0) > 0:
        score += 25
        recs.append("Re-export the image through a basic editor to strip hidden vendor-embedded segments.")

    forg = image_intel.get("forgery") or {}
    if forg.get("available") and forg.get("forgery_likelihood") == "HIGH":
        score += 25
        recs.append("Treat this image with caution — ELA analysis suggests possible localized editing.")
    copy_move = forg.get("copy_move") or {}
    if copy_move.get("available") and copy_move.get("suspicious_match_count", 0) > 0:
        score += 15
        recs.append("Review flagged regions for possible copy-move manipulation.")

    faces = image_intel.get("faces") or {}
    if faces.get("total_faces", 0) > 0:
        score += 10
        recs.append("Faces were detected — handle distribution of this image with privacy in mind.")

    mr = image_intel.get("metadata_risk") or {}
    if mr.get("available") and mr.get("level") in ("High", "Critical"):
        score += 20

    score = min(score, 100)
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not recs:
        recs.append("No specific privacy or integrity concerns were flagged for this image.")

    return level, recs


def build_image_summary(metadata: dict, image_intel: dict) -> ImageAISummary:
    try:
        camera_line = _camera_line(metadata)
        hidden_line = _hidden_metadata_line(image_intel)
        objects_line = _objects_line(image_intel)
        ocr_line = _ocr_line(image_intel)
        forgery_line = _forgery_line(image_intel)
        gps_line = _gps_line(image_intel)

        risk_level, recommendations = _derive_risk(image_intel, metadata)

        signal_count = sum([
            bool(metadata.get("Make") or metadata.get("Camera Model Name")),
            bool((image_intel.get("gps") or {}).get("has_gps")),
            bool((image_intel.get("hidden_data") or {}).get("segments_found")),
            bool((image_intel.get("objects") or {}).get("total_found")),
            bool((image_intel.get("ocr") or {}).get("full_text")),
            bool((image_intel.get("forgery") or {}).get("available")),
        ])
        confidence = "HIGH" if signal_count >= 4 else ("MEDIUM" if signal_count >= 2 else "LOW")
        confidence_note = (
            f"Confidence is {confidence.title()} because {signal_count} independent "
            "data source(s) from this scan were available to summarize."
        )

        return ImageAISummary(
            headline=f"Image Investigation Summary — Risk Level: {risk_level}",
            risk_level=risk_level,
            camera_line=camera_line,
            hidden_metadata_line=hidden_line,
            objects_line=objects_line,
            ocr_line=ocr_line,
            forgery_line=forgery_line,
            gps_line=gps_line,
            recommendations=recommendations,
            confidence=confidence,
            confidence_note=confidence_note,
        )
    except Exception as e:
        return ImageAISummary(available=False, error=str(e))
