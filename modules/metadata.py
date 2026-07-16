import exifread

def extract(path):

    with open(
        path,
        "rb"
    ) as f:

        tags=exifread.process_file(f)

    return tags
"""
metadata.py — Deep file metadata extractor.

Supports
--------
* Images (JPEG, PNG, TIFF, HEIC)  — EXIF, GPS coords, camera model, hidden thumbnails
* PDFs                             — author, creator, dates, embedded files, XMP
* Office (docx, xlsx, pptx)       — core properties, last-modified-by, revision count
* Audio (MP3, FLAC, OGG, M4A)     — ID3/Vorbis tags, encoder, GPS (some cameras)
* Archives                         — file listing, creation timestamp
* Any file                         — MIME type, size, hash (MD5, SHA-1, SHA-256)
"""

from __future__ import annotations

import hashlib
import io
import mimetypes
import os
import zipfile
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class GPSCoords:
    latitude: float
    longitude: float
    altitude: Optional[float]
    maps_url: str      # Google Maps link

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MetadataResult:
    file_path: str
    file_name: str
    file_size_bytes: int
    file_size_human: str
    mime_type: str
    extension: str
    # Hashes
    md5:    str
    sha1:   str
    sha256: str
    # Common
    created:  str
    modified: str
    # Source-specific
    exif:        dict = field(default_factory=dict)
    gps:         Optional[GPSCoords] = None
    camera:      dict = field(default_factory=dict)     # make, model, software, lens
    thumbnails:  list[str] = field(default_factory=list)  # saved thumbnail paths
    pdf_meta:    dict = field(default_factory=dict)
    office_meta: dict = field(default_factory=dict)
    audio_meta:  dict = field(default_factory=dict)
    # Risk flags
    flags: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.gps:
            d["gps"] = self.gps.to_dict()
        return d


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def extract(file_path: str, *, save_thumbnails: bool = True, thumb_dir: str = "/tmp") -> MetadataResult:
    """
    Extract all metadata from *file_path*.

    Args:
        file_path:       Path to the file.
        save_thumbnails: If True, extract and save embedded thumbnails.
        thumb_dir:       Directory to save thumbnails.

    Returns MetadataResult.
    """
    path = Path(file_path)
    if not path.exists():
        return MetadataResult(
            file_path=file_path, file_name=path.name,
            file_size_bytes=0, file_size_human="", mime_type="", extension="",
            md5="", sha1="", sha256="", created="", modified="",
            error=f"File not found: {file_path}",
        )

    # ── Common fields ────────────────────────────────────────────────────────
    stat = path.stat()
    mime, _ = mimetypes.guess_type(str(path))
    mime = mime or "application/octet-stream"
    ext  = path.suffix.lower()
    size = stat.st_size
    md5, sha1, sha256 = _hash_file(path)

    result = MetadataResult(
        file_path=str(path.resolve()),
        file_name=path.name,
        file_size_bytes=size,
        file_size_human=_human_size(size),
        mime_type=mime,
        extension=ext,
        md5=md5, sha1=sha1, sha256=sha256,
        created=_fmt_ts(stat.st_ctime),
        modified=_fmt_ts(stat.st_mtime),
    )

    # ── Route to specialized extractor ──────────────────────────────────────
    if mime.startswith("image/") or ext in (".jpg", ".jpeg", ".tiff", ".tif", ".heic", ".png", ".webp"):
        _extract_image(path, result, save_thumbnails, thumb_dir)
    elif mime == "application/pdf" or ext == ".pdf":
        _extract_pdf(path, result)
    elif ext in (".docx", ".dotx"):
        _extract_office_word(path, result)
    elif ext in (".xlsx", ".xlsm", ".xltx"):
        _extract_office_excel(path, result)
    elif ext in (".pptx", ".potx"):
        _extract_office_pptx(path, result)
    elif mime.startswith("audio/") or ext in (".mp3", ".flac", ".ogg", ".m4a", ".wav", ".aac"):
        _extract_audio(path, result)

    return result


# ─────────────────────────────────────────────
# Image / EXIF
# ─────────────────────────────────────────────

def _extract_image(path: Path, result: MetadataResult, save_thumbs: bool, thumb_dir: str) -> None:
    # ── PIL basic info ───────────────────────────────────────────────────────
    try:
        from PIL import Image as PILImage, ExifTags
        img = PILImage.open(path)
        result.exif["format"]   = img.format
        result.exif["mode"]     = img.mode
        result.exif["width"]    = img.size[0]
        result.exif["height"]   = img.size[1]

        raw_exif = img._getexif() if hasattr(img, "_getexif") else None
        if not raw_exif:
            # Try getexif() for newer Pillow
            try:
                raw_exif = dict(img.getexif())
            except Exception:
                raw_exif = {}

        if raw_exif:
            tag_map = {v: k for k, v in ExifTags.TAGS.items()}
            decoded = {ExifTags.TAGS.get(k, str(k)): v for k, v in raw_exif.items()}

            # Store clean EXIF (skip binary blobs)
            result.exif.update({
                k: str(v) for k, v in decoded.items()
                if not isinstance(v, bytes) and k not in ("MakerNote", "UserComment")
            })

            # Camera info
            result.camera = {
                "make":     decoded.get("Make", ""),
                "model":    decoded.get("Model", ""),
                "software": decoded.get("Software", ""),
                "lens":     decoded.get("LensModel", decoded.get("LensInfo", "")),
                "datetime": decoded.get("DateTime", decoded.get("DateTimeOriginal", "")),
                "flash":    str(decoded.get("Flash", "")),
                "iso":      str(decoded.get("ISOSpeedRatings", "")),
                "exposure": str(decoded.get("ExposureTime", "")),
                "fnumber":  str(decoded.get("FNumber", "")),
                "focal_length": str(decoded.get("FocalLength", "")),
            }

            # GPS
            gps_info = decoded.get("GPSInfo")
            if gps_info:
                result.gps = _parse_gps(gps_info if isinstance(gps_info, dict) else {})
                if result.gps:
                    result.flags.append(
                        f"⚠ GPS coordinates embedded: {result.gps.latitude:.5f}, {result.gps.longitude:.5f}"
                    )

        # Hidden thumbnails
        if save_thumbs:
            result.thumbnails = _extract_thumbnails(img, path, thumb_dir)

    except Exception as exc:
        result.error += f"PIL: {exc}; "

    # ── exifread (more thorough for TIFF/HEIC) ───────────────────────────────
    try:
        import exifread
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        for k, v in tags.items():
            clean_key = k.replace(" ", "_").replace("/", "_")
            if clean_key not in result.exif:
                result.exif[clean_key] = str(v)
    except Exception:
        pass


def _parse_gps(gps_info: dict) -> Optional[GPSCoords]:
    """Convert raw EXIF GPSInfo dict to decimal degrees."""
    try:
        def to_dec(vals, ref):
            d, m, s = [float(v) for v in vals]
            dec = d + m / 60 + s / 3600
            if ref in ("S", "W"):
                dec = -dec
            return dec

        lat = to_dec(gps_info.get(2, (0, 0, 0)), gps_info.get(1, "N"))
        lon = to_dec(gps_info.get(4, (0, 0, 0)), gps_info.get(3, "E"))
        alt_raw = gps_info.get(6)
        alt = float(alt_raw) if alt_raw else None

        maps = f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"
        return GPSCoords(latitude=lat, longitude=lon, altitude=alt, maps_url=maps)
    except Exception:
        return None


def _extract_thumbnails(img, path: Path, thumb_dir: str) -> list[str]:
    """Extract any embedded thumbnails from EXIF (IFD1 / ThumbnailImage)."""
    saved: list[str] = []
    try:
        from PIL import Image as PILImage
        # Pillow embeds thumbnail in _getexif IFD1 — access via TiffImagePlugin
        thumb_data = img.applist if hasattr(img, "applist") else []
        exif_obj = img.getexif()

        # Method: IFD offset 1 contains thumbnail
        ifd1 = exif_obj.get_ifd(0x8769)   # ExifIFD
        if not ifd1:
            return saved

        # Check for JPEG thumbnail
        from PIL.ExifTags import TAGS
        thumb_offset = exif_obj.get_ifd(1)
        if thumb_offset:
            thumb_stream = io.BytesIO()
            try:
                PILImage.open(path).seek(0)
                pass
            except Exception:
                pass

        # Simpler: PIL TiffImagePlugin thumbnail
        if hasattr(img, "tag_v2"):
            thumb_bytes = img.tag_v2.get(513)    # JPEGInterchangeFormat
            if thumb_bytes and isinstance(thumb_bytes, bytes):
                out = os.path.join(thumb_dir, f"{path.stem}_thumb.jpg")
                with open(out, "wb") as f:
                    f.write(thumb_bytes)
                saved.append(out)

    except Exception:
        pass
    return saved


# ─────────────────────────────────────────────
# PDF
# ─────────────────────────────────────────────

def _extract_pdf(path: Path, result: MetadataResult) -> None:
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        meta   = reader.metadata or {}

        result.pdf_meta = {
            "title":          meta.get("/Title", ""),
            "author":         meta.get("/Author", ""),
            "creator":        meta.get("/Creator", ""),
            "producer":       meta.get("/Producer", ""),
            "subject":        meta.get("/Subject", ""),
            "keywords":       meta.get("/Keywords", ""),
            "created":        str(meta.get("/CreationDate", "")),
            "modified":       str(meta.get("/ModDate", "")),
            "pages":          len(reader.pages),
            "encrypted":      reader.is_encrypted,
            "pdf_version":    reader.pdf_header,
        }

        # Embedded files
        embedded = []
        try:
            if "/EmbeddedFiles" in reader.trailer["/Root"]:
                embedded.append("Has embedded files")
                result.flags.append("⚠ PDF contains embedded files")
        except Exception:
            pass
        result.pdf_meta["embedded_files"] = embedded

        # XMP metadata
        try:
            xmp = reader.xmp_metadata
            if xmp:
                result.pdf_meta["xmp"] = {
                    "dc_creator":  str(xmp.dc_creator),
                    "dc_format":   str(xmp.dc_format),
                    "xmp_create":  str(xmp.xmp_create_date),
                    "xmp_modify":  str(xmp.xmp_modify_date),
                }
        except Exception:
            pass

        if result.pdf_meta.get("author"):
            result.flags.append(f"Author embedded: {result.pdf_meta['author']}")

    except Exception as exc:
        result.error += f"PDF: {exc}; "


# ─────────────────────────────────────────────
# Office — Word
# ─────────────────────────────────────────────

def _extract_office_word(path: Path, result: MetadataResult) -> None:
    try:
        from docx import Document
        doc  = Document(str(path))
        core = doc.core_properties
        result.office_meta = _core_props(core)
        _flag_office(result)
    except Exception as exc:
        result.error += f"DOCX: {exc}; "


# ─────────────────────────────────────────────
# Office — Excel
# ─────────────────────────────────────────────

def _extract_office_excel(path: Path, result: MetadataResult) -> None:
    try:
        import openpyxl
        wb   = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
        core = wb.properties
        result.office_meta = {
            "title":          core.title or "",
            "creator":        core.creator or "",
            "last_modified_by": core.lastModifiedBy or "",
            "created":        str(core.created or ""),
            "modified":       str(core.modified or ""),
            "description":    core.description or "",
            "category":       core.category or "",
            "revision":       str(core.revision or ""),
            "sheets":         wb.sheetnames,
        }
        _flag_office(result)
    except Exception as exc:
        result.error += f"XLSX: {exc}; "


# ─────────────────────────────────────────────
# Office — PowerPoint
# ─────────────────────────────────────────────

def _extract_office_pptx(path: Path, result: MetadataResult) -> None:
    try:
        from pptx import Presentation
        prs  = Presentation(str(path))
        core = prs.core_properties
        result.office_meta = _core_props(core)
        result.office_meta["slide_count"] = len(prs.slides)
        _flag_office(result)
    except Exception as exc:
        result.error += f"PPTX: {exc}; "


def _core_props(core) -> dict:
    return {
        "title":            getattr(core, "title", "") or "",
        "author":           getattr(core, "author", "") or "",
        "last_modified_by": getattr(core, "last_modified_by", "") or "",
        "created":          str(getattr(core, "created", "") or ""),
        "modified":         str(getattr(core, "modified", "") or ""),
        "description":      getattr(core, "description", "") or "",
        "keywords":         getattr(core, "keywords", "") or "",
        "category":         getattr(core, "category", "") or "",
        "revision":         str(getattr(core, "revision", "") or ""),
        "subject":          getattr(core, "subject", "") or "",
        "company":          getattr(core, "company", "") or "",
    }


def _flag_office(result: MetadataResult) -> None:
    m = result.office_meta
    if m.get("author"):
        result.flags.append(f"Author: {m['author']}")
    if m.get("last_modified_by"):
        result.flags.append(f"Last modified by: {m['last_modified_by']}")
    if m.get("company"):
        result.flags.append(f"Company: {m['company']}")


# ─────────────────────────────────────────────
# Audio
# ─────────────────────────────────────────────

def _extract_audio(path: Path, result: MetadataResult) -> None:
    try:
        import mutagen
        audio = mutagen.File(str(path))
        if audio is None:
            return
        tags: dict[str, Any] = {}
        for k, v in audio.tags.items() if audio.tags else []:
            tags[str(k)] = str(v) if not isinstance(v, list) else ", ".join(str(x) for x in v)
        result.audio_meta = {
            "tags":     tags,
            "length_s": round(audio.info.length, 2) if hasattr(audio.info, "length") else 0,
            "bitrate":  getattr(audio.info, "bitrate", 0),
            "channels": getattr(audio.info, "channels", 0),
            "sample_rate": getattr(audio.info, "sample_rate", 0),
        }
        # Some cameras embed GPS in audio files
        for key in ("TXXX:GPS", "©xyz", "----:com.apple.iTunes:GPS"):
            if key in tags:
                result.flags.append(f"⚠ GPS tag found in audio: {tags[key]}")
    except Exception as exc:
        result.error += f"Audio: {exc}; "


# ─────────────────────────────────────────────
# Hashing & utilities
# ─────────────────────────────────────────────

def _hash_file(path: Path) -> tuple[str, str, str]:
    h_md5    = hashlib.md5()
    h_sha1   = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h_md5.update(chunk)
                h_sha1.update(chunk)
                h_sha256.update(chunk)
    except Exception:
        pass
    return h_md5.hexdigest(), h_sha1.hexdigest(), h_sha256.hexdigest()


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")