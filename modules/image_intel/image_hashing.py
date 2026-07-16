"""
Image Hashing — cryptographic + perceptual hashes for a single image.

Cryptographic hashes (MD5, SHA256) identify byte-for-byte identical files.
Perceptual hashes (pHash, dHash, aHash, wHash) identify visually similar
images even after resizing, recompression, or minor edits — this is what
powers the Duplicate Image Detection feature.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Optional

try:
    import imagehash
    from PIL import Image
    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False


@dataclass
class ImageHashResult:
    available: bool = True
    error: Optional[str] = None
    md5: str = ""
    sha256: str = ""
    phash: str = ""
    dhash: str = ""
    ahash: str = ""
    whash: str = ""

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "md5": self.md5,
            "sha256": self.sha256,
            "phash": self.phash,
            "dhash": self.dhash,
            "ahash": self.ahash,
            "whash": self.whash,
        }


def compute_hashes(filepath: str) -> ImageHashResult:
    """Compute crypto + perceptual hashes for an image file on disk."""
    if not _DEPS_OK:
        return ImageHashResult(
            available=False,
            error="imagehash / Pillow not installed. Run: pip install ImageHash Pillow",
        )

    try:
        with open(filepath, "rb") as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        img = Image.open(filepath).convert("RGB")
        phash = str(imagehash.phash(img))
        dhash = str(imagehash.dhash(img))
        ahash = str(imagehash.average_hash(img))
        whash = str(imagehash.whash(img))

        return ImageHashResult(
            md5=md5, sha256=sha256,
            phash=phash, dhash=dhash, ahash=ahash, whash=whash,
        )
    except Exception as e:
        return ImageHashResult(available=False, error=str(e))


def hamming_distance(hash_a: str, hash_b: str) -> Optional[int]:
    """Bit-difference between two perceptual hashes of the same type (lower = more similar)."""
    if not _DEPS_OK or not hash_a or not hash_b:
        return None
    try:
        return imagehash.hex_to_hash(hash_a) - imagehash.hex_to_hash(hash_b)
    except Exception:
        return None