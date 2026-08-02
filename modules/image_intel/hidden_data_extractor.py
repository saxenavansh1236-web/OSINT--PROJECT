"""
hidden_data_extractor.py (v2 — multi-vendor)

Detects hidden/embedded binary content in image metadata that never shows
up when the photo is viewed normally. v1 only handled OPPO/OnePlus's
proprietary JSONInfo field. This version adds:

1. OPPO/OnePlus JSONInfo segments        (vendor-specific, named offsets)
2. CIPA MPF (Multi-Picture Format)        (industry STANDARD — Sony, Panasonic,
                                            Fujifilm, and many other vendors)
3. Google Motion Photo                    (Pixel phones — embedded video)
4. Samsung Motion Photo / trailer data     (Samsung-specific embedded video)
5. Generic large-binary fallback          (catches ANY vendor's unknown
                                            proprietary blob ExifTool reports
                                            as binary data, regardless of
                                            whether we recognize the format)

Each detector is independent and wrapped so a failure in one never blocks
the others — consistent with this project's per-feature isolation pattern.
Anything not explicitly recognized is labeled "unrecognized" rather than
guessed at, per this project's evidentiary standard.
"""

import json
import re
import logging

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

# Below this size (bytes), a generic unrecognized binary field is almost
# always a small color-profile curve or config blob, not real content —
# same reasoning as the v1 "collapse tiny segments" logic.
GENERIC_MIN_FLAG_BYTES = 10_000  # 10 KB

# EXIF/metadata field names that are EXPECTED to hold binary-ish or
# moderately large data as part of normal, non-hidden image structure —
# never flag these via the generic fallback (they'd just be noise).
GENERIC_FALLBACK_IGNORE_FIELDS = {
    "ThumbnailImage",     # standard small EXIF thumbnail — expected, usually <20KB
    "BlueTRC", "RedTRC", "GreenTRC",  # ICC color profile curves — small, always present
    "ICCProfile",
    "UserComment",
}


# ---------------------------------------------------------------------------
# 1. OPPO / OnePlus — JSONInfo field
# ---------------------------------------------------------------------------
KNOWN_OPPO_SEGMENT_NAMES = {
    "src.image": {
        "label": "Embedded secondary image",
        "severity": "high",
        "explanation": (
            "A second, separate image is embedded in this file's metadata. "
            "It may show different content than the visible photo (e.g. a "
            "wider crop or an earlier/unprocessed frame)."
        ),
    },
    "rear.depth": {
        "label": "Embedded depth map",
        "severity": "medium",
        "explanation": (
            "A depth map (used for portrait-mode blur) is embedded. On its "
            "own this doesn't reveal visual content, but it confirms "
            "computational-photography data is stored in the file."
        ),
    },
    "front.depth": {
        "label": "Embedded depth map (front camera)",
        "severity": "medium",
        "explanation": "Same as rear.depth, but from the front-facing camera.",
    },
    "watermark": {
        "label": "Embedded watermark render data",
        "severity": "low",
        "explanation": "Data used to render an on-image watermark overlay.",
    },
    "watermark.capture": {
        "label": "Embedded watermark capture data",
        "severity": "low",
        "explanation": "Metadata tied to how/when a watermark was captured.",
    },
    "mesh.coord": {
        "label": "Embedded mesh/coordinate data",
        "severity": "low",
        "explanation": (
            "Geometric mesh data, typically used for portrait/bokeh "
            "rendering. Not visual content on its own."
        ),
    },
}


def _detect_oppo(metadata: dict) -> list:
    raw = metadata.get("JSONInfo")
    if not raw:
        return []
    try:
        segments = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(segments, list):
            return []
    except Exception as e:
        logger.warning("OPPO JSONInfo parse failed: %s", e)
        return []

    findings = []
    minor_count = 0
    minor_bytes = 0

    for seg in segments:
        name = seg.get("name", "")
        length = seg.get("length", 0)
        offset = seg.get("offset", 0)
        known = KNOWN_OPPO_SEGMENT_NAMES.get(name)

        if known:
            findings.append({
                "source": "oppo_jsoninfo", "name": name, "label": known["label"],
                "severity": known["severity"], "size_bytes": length, "offset": offset,
                "explanation": known["explanation"],
            })
        elif length >= 1024:
            findings.append({
                "source": "oppo_jsoninfo", "name": name,
                "label": f"Unrecognized embedded segment ('{name}')",
                "severity": "low", "size_bytes": length, "offset": offset,
                "explanation": (
                    "This vendor-specific segment isn't in our known list yet. "
                    "It may or may not contain visual/personal data."
                ),
            })
        else:
            minor_count += 1
            minor_bytes += length

    if minor_count > 0:
        findings.append({
            "source": "oppo_jsoninfo", "name": "(multiple)",
            "label": f"{minor_count} small vendor config segment(s)",
            "severity": "low", "size_bytes": minor_bytes, "offset": None,
            "explanation": (
                "Small (<1KB each) vendor-specific parameter blobs — not visual "
                "content, typically capture settings or rendering config."
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# 2. CIPA MPF (Multi-Picture Format) — industry standard, many vendors
# ---------------------------------------------------------------------------
def _detect_mpf(metadata: dict) -> list:
    """
    MPF is a real, published standard (CIPA DC-007) used by many camera
    vendors (Sony, Panasonic, Fujifilm, and others, including some Android
    phones) to embed multiple images in one file — e.g. a full-resolution
    original alongside the displayed one. ExifTool surfaces this as
    NumberOfImages / MPImageLength(2/3/...) / MPImageStart(2/3/...).
    """
    findings = []
    try:
        num_images = metadata.get("NumberOfImages")
        if not num_images or int(num_images) <= 1:
            return []

        # MPImageLength / MPImageLength2 / MPImageLength3 ... one per extra image
        length_keys = sorted(
            [k for k in metadata.keys() if re.match(r"^MPImageLength\d*$", k)]
        )
        total_extra_bytes = 0
        count = 0
        for k in length_keys:
            try:
                val = int(metadata[k])
            except (TypeError, ValueError):
                continue
            total_extra_bytes += val
            count += 1

        if count == 0:
            # We know there are multiple images (NumberOfImages > 1) but
            # ExifTool didn't expose per-image sizes on this file — still
            # worth flagging, just without a byte count.
            findings.append({
                "source": "mpf_standard", "name": "MPF", "severity": "medium",
                "label": f"Multi-Picture Format: {num_images} images in one file",
                "size_bytes": 0, "offset": None,
                "explanation": (
                    "This file uses the CIPA MPF standard to store more than "
                    "one image internally (common on Sony/Panasonic/Fujifilm "
                    "and some Android cameras). Extra image(s) beyond the "
                    "displayed one may exist but sizes weren't reported."
                ),
            })
        else:
            findings.append({
                "source": "mpf_standard", "name": "MPF", "severity": "medium",
                "label": f"Multi-Picture Format: {num_images} images in one file",
                "size_bytes": total_extra_bytes, "offset": None,
                "explanation": (
                    "This file uses the CIPA MPF standard (an industry format, "
                    "not vendor-proprietary) to store additional embedded "
                    "image(s) beyond the one you see when opening the file."
                ),
            })
    except Exception as e:
        logger.warning("MPF detection failed: %s", e)
    return findings


# ---------------------------------------------------------------------------
# 3. Google Motion Photo (Pixel and other Android phones)
# ---------------------------------------------------------------------------
def _detect_google_motion_photo(metadata: dict) -> list:
    try:
        is_motion = (
            metadata.get("MotionPhoto") in (1, "1", True)
            or metadata.get("MicroVideo") in (1, "1", True)
            or "MicroVideoOffset" in metadata
        )
        if not is_motion:
            return []

        video_size = metadata.get("MicroVideoOffset") or metadata.get("MotionPhotoVideoLength") or 0
        try:
            video_size = int(video_size)
        except (TypeError, ValueError):
            video_size = 0

        return [{
            "source": "google_motion_photo", "name": "MotionPhoto", "severity": "high",
            "label": "Embedded motion video clip",
            "size_bytes": video_size, "offset": None,
            "explanation": (
                "This is a Google/Android 'Motion Photo' — a short video clip is "
                "embedded after the still image data. Viewing this as a plain "
                "JPEG only shows one still frame; the embedded video (a few "
                "seconds around when the photo was taken) is invisible unless "
                "opened with software that supports Motion Photos."
            ),
        }]
    except Exception as e:
        logger.warning("Motion Photo detection failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# 4. Samsung Motion Photo / trailer data
# ---------------------------------------------------------------------------
def _detect_samsung(metadata: dict) -> list:
    try:
        findings = []
        if metadata.get("SamsungTrailer") or metadata.get("EmbeddedVideoType"):
            findings.append({
                "source": "samsung_trailer", "name": "SamsungTrailer", "severity": "high",
                "label": "Embedded Samsung motion/trailer data",
                "size_bytes": 0, "offset": None,
                "explanation": (
                    "Samsung devices can append extra data (often a short video "
                    "clip, similar to Google Motion Photo) after the visible "
                    "image. Not visible in a normal photo viewer."
                ),
            })
        return findings
    except Exception as e:
        logger.warning("Samsung trailer detection failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# 5. Generic fallback — catches ANY vendor's large unrecognized binary blob
# ---------------------------------------------------------------------------
_BINARY_PATTERN = re.compile(r"\(Binary data (\d+) bytes")


def _detect_generic_large_binary(metadata: dict, already_flagged_fields: set) -> list:
    """
    ExifTool reports fields it can't decode as text as strings like
    "(Binary data 12345 bytes, use -b option to extract)". Any such field,
    above a size threshold and not already explained by a named detector
    above, is flagged generically. This is what makes the tool work for
    vendors we've never specifically coded against — it doesn't need to
    know what the data IS to flag that something unusually large and
    undocumented is present.
    """
    findings = []
    try:
        for key, value in metadata.items():
            if key in GENERIC_FALLBACK_IGNORE_FIELDS or key in already_flagged_fields:
                continue
            if not isinstance(value, str):
                continue
            m = _BINARY_PATTERN.search(value)
            if not m:
                continue
            size = int(m.group(1))
            if size < GENERIC_MIN_FLAG_BYTES:
                continue
            findings.append({
                "source": "generic_fallback", "name": key,
                "label": f"Large unrecognized binary field ('{key}')",
                "severity": "medium" if size < 500_000 else "high",
                "size_bytes": size, "offset": None,
                "explanation": (
                    "This field holds binary data ExifTool can't decode as text, "
                    "and it's large enough to plausibly contain image or video "
                    "content rather than small configuration data. The specific "
                    "vendor format isn't recognized, so this is a generic size-based "
                    "flag, not a confirmed content type."
                ),
            })
    except Exception as e:
        logger.warning("Generic fallback detection failed: %s", e)
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def extract_hidden_segments(metadata: dict) -> dict:
    """
    Runs every detector against the given ExifTool metadata dict and merges
    the results. Vendor-agnostic by design: named detectors handle known
    formats (OPPO, MPF standard, Google/Samsung Motion Photo), and the
    generic fallback catches anything else large enough to matter.
    """
    try:
        all_findings = []

        oppo_findings = _detect_oppo(metadata)
        all_findings.extend(oppo_findings)

        all_findings.extend(_detect_mpf(metadata))
        all_findings.extend(_detect_google_motion_photo(metadata))
        all_findings.extend(_detect_samsung(metadata))

        # Track which raw fields were already explained by a named detector
        # so the generic fallback doesn't double-report the same data
        # (e.g. don't also generically flag "JSONInfo" itself).
        already_flagged_fields = {"JSONInfo"}
        all_findings.extend(_detect_generic_large_binary(metadata, already_flagged_fields))

        if not all_findings:
            return {
                "available": True,
                "segments_found": 0,
                "highest_severity": "low",
                "total_hidden_bytes": 0,
                "findings": [],
            }

        highest = max(all_findings, key=lambda f: SEVERITY_ORDER[f["severity"]])["severity"]
        total_bytes = sum(f["size_bytes"] for f in all_findings)

        return {
            "available": True,
            "segments_found": len(all_findings),
            "highest_severity": highest,
            "total_hidden_bytes": total_bytes,
            "findings": sorted(all_findings, key=lambda f: -SEVERITY_ORDER[f["severity"]]),
        }

    except Exception as e:
        logger.warning("hidden_data_extractor failed: %s", e)
        return {"available": False, "reason": f"Could not analyze embedded segments: {e}"}


def get_risk_contribution(hidden_data_result: dict) -> dict:
    """
    Converts a hidden-data finding into a (points, reason) pair that
    metadata_risk.py folds into its existing 0-100 score. Unchanged
    behavior from v1 — only the detection logic above is new.
    """
    if not hidden_data_result.get("available") or hidden_data_result.get("segments_found", 0) == 0:
        return {"points": 0, "reason": None}

    severity = hidden_data_result["highest_severity"]
    points_map = {"low": 5, "medium": 15, "high": 30}
    size_kb = hidden_data_result["total_hidden_bytes"] // 1024

    reason = (
        f"{hidden_data_result['segments_found']} hidden vendor-embedded segment(s) found "
        f"(~{size_kb} KB total) — highest severity: {severity}"
    )
    return {"points": points_map[severity], "reason": reason}
