"""
modules/investigation/evidence_store.py

Evidence Storage — Phase 2 of the Case Management workflow.

Every case gets its own folder on disk:

    evidence/
    ├── CASE001/
    │   ├── report.pdf
    │   ├── scan.json
    │   ├── logs.txt
    │   └── screenshot_<uuid>.png
    ├── CASE002/
    │   └── ...

Provides:
    - store_file(case_id, file, category)        -> save an uploaded werkzeug FileStorage
    - store_text(case_id, filename, content)      -> save raw text/logs
    - store_json(case_id, filename, data)         -> save a dict as pretty JSON
    - list_evidence(case_id)                      -> list all files with metadata
    - get_evidence_path(case_id, filename)         -> safe absolute path (or None)
    - delete_evidence(case_id, filename)           -> remove a file
    - case_folder(case_id)                        -> the CASE### folder path (creates it)

Security (matches the same conventions used by /image-osint in app.py):
    - Extension allow-list per category
    - secure_filename() sanitisation
    - UUID-prefixed names to avoid collisions/overwrites
    - Path-containment check before any read/write/delete
    - Hard size cap per file
"""

import os
import json
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
EVIDENCE_ROOT = os.environ.get("EVIDENCE_ROOT", "evidence")

ALLOWED_EXTENSIONS = {
    "pdf":        {"pdf"},
    "screenshot": {"png", "jpg", "jpeg", "webp", "gif", "bmp"},
    "json":       {"json"},
    "log":        {"txt", "log"},
    "other":      {"pdf", "png", "jpg", "jpeg", "webp", "gif", "bmp",
                    "json", "txt", "log", "csv", "zip"},
}

MAX_FILE_SIZE_MB = 25

os.makedirs(EVIDENCE_ROOT, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def case_folder(case_id: int) -> str:
    """Returns (and creates) the evidence folder for a case, e.g. evidence/CASE001"""
    folder_name = f"CASE{int(case_id):03d}"
    path = os.path.join(EVIDENCE_ROOT, folder_name)
    os.makedirs(path, exist_ok=True)
    return path


def _safe_path(case_id: int, filename: str) -> str:
    """Resolve a filename inside a case folder, guarding against path traversal."""
    folder = os.path.abspath(case_folder(case_id))
    candidate = os.path.abspath(os.path.join(folder, filename))
    if not candidate.startswith(folder + os.sep) and candidate != folder:
        raise ValueError("Invalid evidence path.")
    return candidate


def _allowed_ext(filename: str, category: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS.get(category, ALLOWED_EXTENSIONS["other"])


def _human_size(num_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f}{unit}" if unit != "B" else f"{num_bytes}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}TB"


def _category_for_ext(ext: str) -> str:
    for cat, exts in ALLOWED_EXTENSIONS.items():
        if cat != "other" and ext in exts:
            return cat
    return "other"


# ---------------------------------------------------------------------------
# Store: uploaded file (FileStorage from Flask's request.files)
# ---------------------------------------------------------------------------
def store_file(case_id: int, file, category: str = "other") -> dict:
    """
    Save an uploaded file (Flask FileStorage) into the case's evidence folder.
    Returns a dict describing the stored evidence, or raises ValueError on
    validation failure (bad extension, too large, empty filename, etc).
    """
    if not file or not getattr(file, "filename", ""):
        raise ValueError("No file provided.")

    if not _allowed_ext(file.filename, category):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS.get(category, ALLOWED_EXTENSIONS["other"])))
        raise ValueError(f"Invalid file type for '{category}'. Allowed: {allowed}")

    file.seek(0, os.SEEK_END)
    size_bytes = file.tell()
    file.seek(0)
    if size_bytes > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise ValueError(f"File too large. Max {MAX_FILE_SIZE_MB}MB.")

    safe_name = secure_filename(file.filename)
    if not safe_name:
        raise ValueError("Invalid filename.")

    unique_name = f"{category}_{uuid.uuid4().hex[:8]}_{safe_name}"
    dest_path = _safe_path(case_id, unique_name)

    file.save(dest_path)

    return {
        "filename": unique_name,
        "original_name": safe_name,
        "category": category,
        "size": size_bytes,
        "size_human": _human_size(size_bytes),
        "stored_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Store: raw text (logs, notes exports, etc.)
# ---------------------------------------------------------------------------
def store_text(case_id: int, filename: str, content: str, category: str = "log") -> dict:
    safe_name = secure_filename(filename) or f"log_{uuid.uuid4().hex[:8]}.txt"
    if not _allowed_ext(safe_name, category):
        safe_name += ".txt"

    dest_path = _safe_path(case_id, safe_name)
    with open(dest_path, "w", encoding="utf-8") as f:
        f.write(content or "")

    size_bytes = os.path.getsize(dest_path)
    return {
        "filename": safe_name,
        "original_name": safe_name,
        "category": category,
        "size": size_bytes,
        "size_human": _human_size(size_bytes),
        "stored_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Store: dict as JSON (scan snapshots, API results, etc.)
# ---------------------------------------------------------------------------
def store_json(case_id: int, filename: str, data: dict, category: str = "json") -> dict:
    safe_name = secure_filename(filename) or f"data_{uuid.uuid4().hex[:8]}.json"
    if not safe_name.lower().endswith(".json"):
        safe_name += ".json"

    dest_path = _safe_path(case_id, safe_name)
    with open(dest_path, "w", encoding="utf-8") as f:
        json.dump(data or {}, f, indent=2, default=str)

    size_bytes = os.path.getsize(dest_path)
    return {
        "filename": safe_name,
        "original_name": safe_name,
        "category": category,
        "size": size_bytes,
        "size_human": _human_size(size_bytes),
        "stored_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# List all evidence for a case
# ---------------------------------------------------------------------------
def list_evidence(case_id: int) -> list:
    folder = case_folder(case_id)
    items = []
    try:
        for fname in sorted(os.listdir(folder)):
            fpath = os.path.join(folder, fname)
            if not os.path.isfile(fpath):
                continue
            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            stat = os.stat(fpath)
            items.append({
                "filename": fname,
                "category": _category_for_ext(ext),
                "extension": ext,
                "size": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "modified_at": datetime.utcfromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
    except FileNotFoundError:
        pass
    # newest first
    items.sort(key=lambda x: x["modified_at"], reverse=True)
    return items


# ---------------------------------------------------------------------------
# Get a safe path for download (returns None if missing/invalid)
# ---------------------------------------------------------------------------
def get_evidence_path(case_id: int, filename: str):
    try:
        path = _safe_path(case_id, filename)
    except ValueError:
        return None
    if not os.path.isfile(path):
        return None
    return path


# ---------------------------------------------------------------------------
# Delete a single evidence file
# ---------------------------------------------------------------------------
def delete_evidence(case_id: int, filename: str) -> bool:
    try:
        path = _safe_path(case_id, filename)
    except ValueError:
        return False
    if os.path.isfile(path):
        try:
            os.remove(path)
            return True
        except OSError:
            return False
    return False


# ---------------------------------------------------------------------------
# Convenience: snapshot a case's current scan_data + notes as evidence
# ---------------------------------------------------------------------------
def snapshot_case(case_id: int, scan_data: dict = None, notes_text: str = None) -> list:
    """
    Called after case creation or on-demand from the Evidence Center to save
    the current scan_data as JSON and notes as a text log, in one go.
    Returns the list of evidence dicts created.
    """
    created = []
    if scan_data:
        created.append(store_json(case_id, "scan.json", scan_data, category="json"))
    if notes_text:
        created.append(store_text(case_id, "logs.txt", notes_text, category="log"))
    return created


def evidence_summary(case_id: int) -> dict:
    """Quick counts for dashboard/case-detail widgets."""
    items = list_evidence(case_id)
    summary = {"total": len(items), "total_size": sum(i["size"] for i in items)}
    for cat in ALLOWED_EXTENSIONS.keys():
        summary[cat] = sum(1 for i in items if i["category"] == cat)
    summary["total_size_human"] = _human_size(summary["total_size"])
    return summary