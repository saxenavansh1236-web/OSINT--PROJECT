"""
Duplicate Image Detection — compares the perceptual hash of the current
image against every hash previously recorded by the platform, surfacing
near-duplicates (recompressed, resized, re-cropped, or re-watermarked
copies) rather than only byte-identical files.

Storage: a flat JSON file (image_hash_store.json) mapping
    { sha256: {"phash": ..., "dhash": ..., "filename": ..., "first_seen": ..., "case_ids": [...]} }
This keeps it dependency-free (no new DB tables) and safe to delete/reset.
"""
from __future__ import annotations
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .image_hashing import hamming_distance

_STORE_PATH = os.path.join("data", "image_hash_store.json")
_LOCK = threading.Lock()

# Distance thresholds for pHash (64-bit hash, max distance 64)
SIMILARITY_THRESHOLDS = {
    "identical": 0,     # bit-for-bit same perceptual hash
    "near_duplicate": 6,  # minor recompression / resize
    "similar": 12,       # cropped, watermarked, filtered
}


@dataclass
class DuplicateMatch:
    sha256: str
    filename: str
    first_seen: str
    distance: int
    similarity_label: str

    def to_dict(self):
        return {
            "sha256": self.sha256,
            "filename": self.filename,
            "first_seen": self.first_seen,
            "distance": self.distance,
            "similarity_label": self.similarity_label,
        }


@dataclass
class DuplicateDetectionResult:
    available: bool = True
    error: Optional[str] = None
    is_new: bool = True
    total_indexed: int = 0
    matches: list = field(default_factory=list)

    def to_dict(self):
        return {
            "available": self.available,
            "error": self.error,
            "is_new": self.is_new,
            "total_indexed": self.total_indexed,
            "matches": [m.to_dict() for m in self.matches],
        }


def _load_store() -> dict:
    if not os.path.exists(_STORE_PATH):
        return {}
    try:
        with open(_STORE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_store(store: dict):
    os.makedirs(os.path.dirname(_STORE_PATH), exist_ok=True)
    with open(_STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)


def _label_for_distance(dist: int) -> str:
    if dist <= SIMILARITY_THRESHOLDS["identical"]:
        return "identical"
    if dist <= SIMILARITY_THRESHOLDS["near_duplicate"]:
        return "near_duplicate"
    if dist <= SIMILARITY_THRESHOLDS["similar"]:
        return "similar"
    return "different"


def check_and_index(sha256: str, phash: str, filename: str) -> DuplicateDetectionResult:
    """
    Check the current image's hash against the store, then index it
    (whether or not a match was found) so future scans can find it too.
    """
    if not phash:
        return DuplicateDetectionResult(available=False, error="No perceptual hash available.")

    with _LOCK:
        store = _load_store()
        matches = []

        for existing_sha, entry in store.items():
            if existing_sha == sha256:
                continue  # exact same file already indexed; not a "match", it's a re-scan
            dist = hamming_distance(phash, entry.get("phash", ""))
            if dist is not None and dist <= SIMILARITY_THRESHOLDS["similar"]:
                matches.append(DuplicateMatch(
                    sha256=existing_sha,
                    filename=entry.get("filename", "unknown"),
                    first_seen=entry.get("first_seen", "unknown"),
                    distance=dist,
                    similarity_label=_label_for_distance(dist),
                ))

        matches.sort(key=lambda m: m.distance)

        is_new = sha256 not in store
        if is_new:
            store[sha256] = {
                "phash": phash,
                "filename": filename,
                "first_seen": datetime.utcnow().isoformat() + "Z",
            }
            _save_store(store)

        return DuplicateDetectionResult(
            is_new=is_new,
            total_indexed=len(store),
            matches=matches[:10],
        )