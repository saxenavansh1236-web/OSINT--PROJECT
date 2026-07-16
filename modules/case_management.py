"""
case_management.py
Save, manage, and export OSINT investigations as cases.
Integrates with the Flask app's SQLAlchemy database.
"""

import json
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

from flask import current_app
from models import db


# ── SQLAlchemy Model (add this to your models.py) ────────────────────────────
# Paste this class into models.py:
#
# class Case(db.Model):
#     __tablename__ = "cases"
#     id           = db.Column(db.Integer, primary_key=True)
#     title        = db.Column(db.String(200), nullable=False)
#     target       = db.Column(db.String(500), nullable=False)
#     description  = db.Column(db.Text, default="")
#     status       = db.Column(db.String(50), default="open")    # open/closed/archived
#     priority     = db.Column(db.String(20), default="medium")  # low/medium/high/critical
#     tags         = db.Column(db.Text, default="")              # comma-separated
#     scan_data    = db.Column(db.Text, default="{}")            # JSON blob of last scan
#     notes        = db.Column(db.Text, default="")
#     created_by   = db.Column(db.String(100), default="admin")
#     created_at   = db.Column(db.DateTime, default=datetime.utcnow)
#     updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
#
# class CaseNote(db.Model):
#     __tablename__ = "case_notes"
#     id         = db.Column(db.Integer, primary_key=True)
#     case_id    = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
#     content    = db.Column(db.Text, nullable=False)
#     author     = db.Column(db.String(100), default="admin")
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from models import Case, CaseNote
    _HAS_CASE_MODEL = True
except ImportError:
    _HAS_CASE_MODEL = False


@dataclass
class CaseExport:
    case_id: int
    title: str
    target: str
    status: str
    priority: str
    tags: List[str]
    description: str
    notes: List[Dict]
    scan_summary: Dict
    created_at: str
    exported_at: str

    def to_dict(self):
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_text_report(self) -> str:
        lines = [
            "=" * 60,
            f"OSINT CASE REPORT",
            "=" * 60,
            f"Case ID   : {self.case_id}",
            f"Title     : {self.title}",
            f"Target    : {self.target}",
            f"Status    : {self.status.upper()}",
            f"Priority  : {self.priority.upper()}",
            f"Tags      : {', '.join(self.tags) or 'None'}",
            f"Created   : {self.created_at}",
            f"Exported  : {self.exported_at}",
            "",
            "DESCRIPTION",
            "-" * 40,
            self.description or "(none)",
            "",
            "SCAN SUMMARY",
            "-" * 40,
        ]

        for key, val in self.scan_summary.items():
            if isinstance(val, (dict, list)):
                lines.append(f"  {key}: {json.dumps(val, default=str)[:120]}")
            else:
                lines.append(f"  {key}: {val}")

        if self.notes:
            lines += ["", "NOTES", "-" * 40]
            for n in self.notes:
                lines.append(f"[{n.get('created_at','')}] {n.get('author','?')}: {n.get('content','')}")

        lines.append("=" * 60)
        return "\n".join(lines)


# ── Case CRUD helpers ─────────────────────────────────────────────────────────

def create_case(title: str, target: str, scan_data: dict = None,
                description: str = "", priority: str = "medium",
                tags: List[str] = None, created_by: str = "admin") -> Optional[int]:
    """
    Create a new investigation case.
    Returns the new case ID or None on failure.
    """
    if not _HAS_CASE_MODEL:
        raise RuntimeError("Case model not found. Add Case and CaseNote to models.py")
    try:
        case = Case(
            title=title,
            target=target,
            description=description,
            status="open",
            priority=priority,
            tags=",".join(tags) if tags else "",
            scan_data=json.dumps(scan_data or {}, default=str),
            created_by=created_by,
        )
        db.session.add(case)
        db.session.commit()
        return case.id
    except Exception as e:
        db.session.rollback()
        print(f"[case_management/create] {e}")
        return None


def get_case(case_id: int) -> Optional[Dict]:
    """Fetch a single case by ID."""
    if not _HAS_CASE_MODEL:
        return None
    try:
        case = Case.query.get(case_id)
        if not case:
            return None
        return _case_to_dict(case)
    except Exception as e:
        print(f"[case_management/get] {e}")
        return None


def list_cases(status: str = None, priority: str = None,
               search: str = None, limit: int = 50) -> List[Dict]:
    """List cases with optional filters."""
    if not _HAS_CASE_MODEL:
        return []
    try:
        q = Case.query
        if status:
            q = q.filter_by(status=status)
        if priority:
            q = q.filter_by(priority=priority)
        if search:
            q = q.filter(
                Case.title.ilike(f"%{search}%") |
                Case.target.ilike(f"%{search}%") |
                Case.description.ilike(f"%{search}%")
            )
        cases = q.order_by(Case.created_at.desc()).limit(limit).all()
        return [_case_to_dict(c) for c in cases]
    except Exception as e:
        print(f"[case_management/list] {e}")
        return []


def update_case(case_id: int, **kwargs) -> bool:
    """Update case fields. Accepts: title, description, status, priority, tags, notes, scan_data."""
    if not _HAS_CASE_MODEL:
        return False
    try:
        case = Case.query.get(case_id)
        if not case:
            return False
        allowed = {"title", "description", "status", "priority", "tags", "notes"}
        for key, val in kwargs.items():
            if key in allowed:
                if key == "tags" and isinstance(val, list):
                    val = ",".join(val)
                setattr(case, key, val)
            elif key == "scan_data" and isinstance(val, dict):
                case.scan_data = json.dumps(val, default=str)
        case.updated_at = datetime.utcnow()
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[case_management/update] {e}")
        return False


def delete_case(case_id: int) -> bool:
    """Delete a case and its notes."""
    if not _HAS_CASE_MODEL:
        return False
    try:
        CaseNote.query.filter_by(case_id=case_id).delete()
        case = Case.query.get(case_id)
        if case:
            db.session.delete(case)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[case_management/delete] {e}")
        return False


def add_note(case_id: int, content: str, author: str = "admin") -> bool:
    """Add a note to a case."""
    if not _HAS_CASE_MODEL:
        return False
    try:
        note = CaseNote(case_id=case_id, content=content, author=author)
        db.session.add(note)
        # Update case updated_at
        case = Case.query.get(case_id)
        if case:
            case.updated_at = datetime.utcnow()
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[case_management/add_note] {e}")
        return False


def get_notes(case_id: int) -> List[Dict]:
    """Get all notes for a case."""
    if not _HAS_CASE_MODEL:
        return []
    try:
        notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at).all()
        return [
            {
                "id": n.id,
                "content": n.content,
                "author": n.author,
                "created_at": n.created_at.strftime("%Y-%m-%d %H:%M:%S") if n.created_at else "",
            }
            for n in notes
        ]
    except Exception as e:
        print(f"[case_management/get_notes] {e}")
        return []


def export_case(case_id: int) -> Optional[CaseExport]:
    """Export a full case with notes and scan data."""
    if not _HAS_CASE_MODEL:
        return None
    try:
        case = Case.query.get(case_id)
        if not case:
            return None
        notes = get_notes(case_id)
        scan_data = {}
        try:
            scan_data = json.loads(case.scan_data or "{}")
        except Exception:
            pass

        # Build summary from scan data (top-level counts)
        summary = {}
        for key in ("ip", "target", "breach", "username", "subs", "geo",
                    "risk_score", "primary_provider", "open_ports"):
            if key in scan_data:
                val = scan_data[key]
                if isinstance(val, list):
                    summary[key] = f"{len(val)} items"
                elif isinstance(val, dict):
                    summary[key] = str(val.get("total_score") or val.get("primary_provider") or "present")
                else:
                    summary[key] = str(val)

        return CaseExport(
            case_id=case.id,
            title=case.title,
            target=case.target,
            status=case.status,
            priority=case.priority,
            tags=[t.strip() for t in (case.tags or "").split(",") if t.strip()],
            description=case.description or "",
            notes=notes,
            scan_summary=summary,
            created_at=case.created_at.strftime("%Y-%m-%d %H:%M:%S") if case.created_at else "",
            exported_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
    except Exception as e:
        print(f"[case_management/export] {e}")
        return None


def _case_to_dict(case) -> Dict:
    return {
        "id": case.id,
        "title": case.title,
        "target": case.target,
        "description": case.description or "",
        "status": case.status or "open",
        "priority": case.priority or "medium",
        "tags": [t.strip() for t in (case.tags or "").split(",") if t.strip()],
        "created_by": case.created_by or "admin",
        "created_at": case.created_at.strftime("%Y-%m-%d %H:%M:%S") if case.created_at else "",
        "updated_at": case.updated_at.strftime("%Y-%m-%d %H:%M:%S") if case.updated_at else "",
        "notes_count": CaseNote.query.filter_by(case_id=case.id).count() if _HAS_CASE_MODEL else 0,
    }