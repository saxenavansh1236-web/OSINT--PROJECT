"""
modules/image_intel/similarity_search.py
Near-duplicate / visual similarity search across the same phash index
used by duplicate_detection.py, but returns a ranked top-N list with
similarity percentages instead of a binary "duplicate or not" check.
Read-only against the shared store — does not index the current image
again (duplicate_detection.py already owns writes).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import json
import os

from .image_hashing import hamming_distance

_STORE_PATH = os.path.join("data", "image_hash_store.json")


@dataclass
class SimilarityMatch:
    sha256: str
    filename: str
    first_seen: str
    similarity_percent: float

    def to_dict(self):
        return {
            "sha256": self.sha256, "filename": self.filename,
            "first_seen": self.first_seen, "similarity_percent": self.similarity_percent,
        }


@dataclass
class SimilaritySearchResult:
    available: bool = True
    error: Optional[str] = None
    index_size: int = 0
    matches: list = field(default_factory=list)
    note: str = "Compares against images previously scanned on this instance only — not an internet-wide reverse image search."

    def to_dict(self):
        return {
            "available": self.available, "error": self.error,
            "index_size": self.index_size,
            "matches": [m.to_dict() for m in self.matches],
            "note": self.note,
        }


def _load_store() -> dict:
    if not os.path.exists(_STORE_PATH):
        return {}
    try:
        with open(_STORE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def search(sha256: str, phash: str, top_n: int = 5, max_distance: int = 20) -> SimilaritySearchResult:
    if not phash:
        return SimilaritySearchResult(available=False, error="No perceptual hash available for comparison.")

    try:
        store = _load_store()
        scored = []
        for existing_sha, entry in store.items():
            if existing_sha == sha256:
                continue
            dist = hamming_distance(phash, entry.get("phash", ""))
            if dist is not None and dist <= max_distance:
                similarity_pct = round((1 - dist / 64) * 100, 1)  # 64-bit phash
                scored.append(SimilarityMatch(
                    sha256=existing_sha,
                    filename=entry.get("filename", "unknown"),
                    first_seen=entry.get("first_seen", "unknown"),
                    similarity_percent=similarity_pct,
                ))

        scored.sort(key=lambda m: m.similarity_percent, reverse=True)

        return SimilaritySearchResult(index_size=len(store), matches=scored[:top_n])
    except Exception as e:
        return SimilaritySearchResult(available=False, error=str(e))