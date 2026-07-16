"""
modules/investigation/case_engine.py

Case Management System — turns a one-off scan into a tracked investigation.

Provides:
    - Case / CaseScan / CaseNote SQLAlchemy models
    - A Flask Blueprint ("investigation") with routes for:
        GET  /cases                  -> case list (filter/search)
        GET  /cases/new              -> create case form
        POST /cases/new              -> create case
        GET  /cases/<id>             -> case detail (notes, attached scans, timeline)
        POST /cases/<id>/status      -> update status
        POST /cases/<id>/priority    -> update priority
        POST /cases/<id>/attach      -> attach an existing scan (History row) to the case
        POST /cases/<id>/note        -> add an investigator note
        POST /cases/<id>/delete      -> delete a case (admin only)

Integration:
    1. Drop this file at modules/investigation/case_engine.py
       (add an empty modules/investigation/__init__.py alongside it).
    2. In models.py, import `db` from the same SQLAlchemy instance used by the
       rest of the app and make sure Case/CaseScan/CaseNote below use it —
       OR simply import `db` from models.py here (see the try/except import
       block) so everything shares one metadata/session.
    3. In app.py:
           from modules.investigation.case_engine import investigation_bp, init_case_engine
           init_case_engine(app, db)
           app.register_blueprint(investigation_bp)
    4. Run a migration / db.create_all() once to create the new tables.
"""

from datetime import datetime
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, session, jsonify, abort
)

# ---------------------------------------------------------------------------
# Shared db handle
# ---------------------------------------------------------------------------
# The rest of the platform (models.py) already defines a single SQLAlchemy()
# instance. Import it so Case/CaseScan/CaseNote live in the same metadata and
# can be created with the same db.create_all() call. Fallback to a fresh
# instance only if this module is run/imported standalone (e.g. for tests).
try:
    from models import db, History, User, AuditLog  # type: ignore
except Exception:  # pragma: no cover - standalone/test fallback
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()
    History = None
    User = None
    AuditLog = None

investigation_bp = Blueprint(
    "investigation",
    __name__,
    template_folder="../../templates/investigation",
    url_prefix="/cases",
)

VALID_STATUSES = ["open", "in_progress", "on_hold", "closed", "archived"]
VALID_PRIORITIES = ["low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(20), nullable=False, default="open", index=True)
    priority = db.Column(db.String(20), nullable=False, default="medium", index=True)
    tags = db.Column(db.String(300), nullable=True)  # comma-separated

    created_by = db.Column(db.String(80), nullable=True)
    assigned_to = db.Column(db.String(80), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)

    scans = db.relationship(
        "CaseScan", backref="case", cascade="all, delete-orphan",
        order_by="CaseScan.attached_at.desc()"
    )
    notes = db.relationship(
        "CaseNote", backref="case", cascade="all, delete-orphan",
        order_by="CaseNote.created_at.desc()"
    )

    def tag_list(self):
        return [t.strip() for t in (self.tags or "").split(",") if t.strip()]

    def to_dict(self):
        return {
            "id": self.id,
            "case_number": self.case_number,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "priority": self.priority,
            "tags": self.tag_list(),
            "created_by": self.created_by,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "scan_count": len(self.scans),
            "note_count": len(self.notes),
        }


class CaseScan(db.Model):
    """Links a Case to a scan result (History row) — many scans per case."""
    __tablename__ = "case_scans"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    history_id = db.Column(db.Integer, nullable=True)  # FK to History.id (loose to avoid model coupling)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=True)
    attached_by = db.Column(db.String(80), nullable=True)
    attached_at = db.Column(db.DateTime, default=datetime.utcnow)


class CaseNote(db.Model):
    __tablename__ = "case_notes"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    author = db.Column(db.String(80), nullable=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _current_user():
    return session.get("username") or session.get("user") or "unknown"


def _login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id") and not session.get("username"):
            flash("Please log in to access case management.", "error")
            return redirect(url_for("admin_login") if "admin_login" in
                             _registered_endpoints() else url_for("investigation.cases"))
        return view(*args, **kwargs)
    return wrapped


def _registered_endpoints():
    try:
        from flask import current_app
        return current_app.view_functions.keys()
    except Exception:
        return []


def _audit(action, target=None, details=None):
    """Best-effort audit log write — never blocks the request if it fails."""
    if AuditLog is None:
        return
    try:
        entry = AuditLog(
            username=_current_user(),
            action=action,
            target=target or "",
            details=details or "",
            ip_address=request.remote_addr,
            timestamp=datetime.utcnow(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


def generate_case_number():
    """CASE-YYYY-#### sequential per year."""
    year = datetime.utcnow().year
    prefix = f"CASE-{year}-"
    last = (
        Case.query.filter(Case.case_number.like(f"{prefix}%"))
        .order_by(Case.id.desc())
        .first()
    )
    if last and last.case_number.startswith(prefix):
        try:
            n = int(last.case_number.replace(prefix, "")) + 1
        except ValueError:
            n = 1
    else:
        n = 1
    return f"{prefix}{n:04d}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@investigation_bp.route("/", methods=["GET"])
@_login_required
def cases():
    """Case list with search / status / priority filters."""
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    priority = request.args.get("priority", "").strip()

    query = Case.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(Case.title.ilike(like), Case.case_number.ilike(like), Case.tags.ilike(like))
        )
    if status in VALID_STATUSES:
        query = query.filter_by(status=status)
    if priority in VALID_PRIORITIES:
        query = query.filter_by(priority=priority)

    all_cases = query.order_by(Case.updated_at.desc()).all()

    stats = {
        "total": Case.query.count(),
        "open": Case.query.filter_by(status="open").count(),
        "in_progress": Case.query.filter_by(status="in_progress").count(),
        "closed": Case.query.filter_by(status="closed").count(),
        "critical": Case.query.filter_by(priority="critical").count(),
    }

    return render_template(
        "investigation/cases.html",
        cases=all_cases,
        stats=stats,
        q=q,
        status=status,
        priority=priority,
        statuses=VALID_STATUSES,
        priorities=VALID_PRIORITIES,
    )


@investigation_bp.route("/new", methods=["GET", "POST"])
@_login_required
def create_case():
    if request.method == "GET":
        return render_template(
            "investigation/create_case.html",
            statuses=VALID_STATUSES,
            priorities=VALID_PRIORITIES,
        )

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    priority = request.form.get("priority", "medium").strip()
    tags = request.form.get("tags", "").strip()
    assigned_to = request.form.get("assigned_to", "").strip()
    seed_target = request.form.get("seed_target", "").strip()

    if not title:
        flash("Case title is required.", "error")
        return render_template(
            "investigation/create_case.html",
            statuses=VALID_STATUSES,
            priorities=VALID_PRIORITIES,
            form=request.form,
        )

    if priority not in VALID_PRIORITIES:
        priority = "medium"

    new_case = Case(
        case_number=generate_case_number(),
        title=title,
        description=description,
        priority=priority,
        tags=tags,
        created_by=_current_user(),
        assigned_to=assigned_to or None,
        status="open",
    )
    db.session.add(new_case)
    db.session.commit()

    # Optional: seed the case with an initial target / scan reference
    if seed_target:
        db.session.add(CaseScan(
            case_id=new_case.id,
            target=seed_target,
            scan_type=request.form.get("seed_scan_type", "manual"),
            attached_by=_current_user(),
        ))
        db.session.commit()

    _audit("case_created", target=new_case.case_number,
           details=f"title={title} priority={priority}")

    flash(f"Case {new_case.case_number} created.", "success")
    return redirect(url_for("investigation.case_detail", case_id=new_case.id))


@investigation_bp.route("/<int:case_id>", methods=["GET"])
@_login_required
def case_detail(case_id):
    case = Case.query.get_or_404(case_id)
    return render_template(
        "investigation/case_detail.html",
        case=case,
        statuses=VALID_STATUSES,
        priorities=VALID_PRIORITIES,
    )


@investigation_bp.route("/<int:case_id>/status", methods=["POST"])
@_login_required
def update_status(case_id):
    case = Case.query.get_or_404(case_id)
    new_status = request.form.get("status", "")
    if new_status not in VALID_STATUSES:
        flash("Invalid status.", "error")
        return redirect(url_for("investigation.case_detail", case_id=case_id))

    old_status = case.status
    case.status = new_status
    case.updated_at = datetime.utcnow()
    if new_status == "closed":
        case.closed_at = datetime.utcnow()
    elif old_status == "closed" and new_status != "closed":
        case.closed_at = None
    db.session.commit()

    _audit("case_status_changed", target=case.case_number,
           details=f"{old_status} -> {new_status}")

    flash(f"Status updated to {new_status.replace('_', ' ').title()}.", "success")
    return redirect(url_for("investigation.case_detail", case_id=case_id))


@investigation_bp.route("/<int:case_id>/priority", methods=["POST"])
@_login_required
def update_priority(case_id):
    case = Case.query.get_or_404(case_id)
    new_priority = request.form.get("priority", "")
    if new_priority not in VALID_PRIORITIES:
        flash("Invalid priority.", "error")
        return redirect(url_for("investigation.case_detail", case_id=case_id))

    old_priority = case.priority
    case.priority = new_priority
    case.updated_at = datetime.utcnow()
    db.session.commit()

    _audit("case_priority_changed", target=case.case_number,
           details=f"{old_priority} -> {new_priority}")

    flash(f"Priority updated to {new_priority.title()}.", "success")
    return redirect(url_for("investigation.case_detail", case_id=case_id))


@investigation_bp.route("/<int:case_id>/attach", methods=["POST"])
@_login_required
def attach_scan(case_id):
    """Attach an existing scan result (by target, and optionally a History.id) to a case."""
    case = Case.query.get_or_404(case_id)
    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "").strip()
    history_id = request.form.get("history_id", "").strip()

    if not target:
        flash("Target is required to attach a scan.", "error")
        return redirect(url_for("investigation.case_detail", case_id=case_id))

    cs = CaseScan(
        case_id=case.id,
        history_id=int(history_id) if history_id.isdigit() else None,
        target=target,
        scan_type=scan_type or "scan",
        attached_by=_current_user(),
    )
    db.session.add(cs)
    case.updated_at = datetime.utcnow()
    db.session.commit()

    _audit("scan_attached_to_case", target=case.case_number, details=f"target={target}")

    flash(f"Scan for '{target}' attached to case.", "success")
    return redirect(url_for("investigation.case_detail", case_id=case_id))


@investigation_bp.route("/<int:case_id>/note", methods=["POST"])
@_login_required
def add_note(case_id):
    case = Case.query.get_or_404(case_id)
    content = request.form.get("content", "").strip()
    if not content:
        flash("Note cannot be empty.", "error")
        return redirect(url_for("investigation.case_detail", case_id=case_id))

    note = CaseNote(case_id=case.id, author=_current_user(), content=content)
    db.session.add(note)
    case.updated_at = datetime.utcnow()
    db.session.commit()

    _audit("case_note_added", target=case.case_number)

    flash("Note added.", "success")
    return redirect(url_for("investigation.case_detail", case_id=case_id))


@investigation_bp.route("/<int:case_id>/delete", methods=["POST"])
@_login_required
def delete_case(case_id):
    # Restrict to admins if a role is present in session
    if session.get("role") not in (None, "admin"):
        abort(403)

    case = Case.query.get_or_404(case_id)
    case_number = case.case_number
    db.session.delete(case)
    db.session.commit()

    _audit("case_deleted", target=case_number)

    flash(f"Case {case_number} deleted.", "success")
    return redirect(url_for("investigation.cases"))


# ---------------------------------------------------------------------------
# JSON API (for dashboard widgets / link graph integration)
# ---------------------------------------------------------------------------
@investigation_bp.route("/api/list", methods=["GET"])
@_login_required
def api_list_cases():
    return jsonify([c.to_dict() for c in Case.query.order_by(Case.updated_at.desc()).all()])


@investigation_bp.route("/api/<int:case_id>", methods=["GET"])
@_login_required
def api_case_detail(case_id):
    case = Case.query.get_or_404(case_id)
    data = case.to_dict()
    data["scans"] = [
        {"target": s.target, "scan_type": s.scan_type, "attached_by": s.attached_by,
         "attached_at": s.attached_at.isoformat() if s.attached_at else None}
        for s in case.scans
    ]
    data["notes"] = [
        {"author": n.author, "content": n.content,
         "created_at": n.created_at.isoformat() if n.created_at else None}
        for n in case.notes
    ]
    return jsonify(data)


# ---------------------------------------------------------------------------
# App wiring helper
# ---------------------------------------------------------------------------
def init_case_engine(app, db_instance=None):
    """
    Call once from app.py after the Flask app and db are created:

        from modules.investigation.case_engine import investigation_bp, init_case_engine
        init_case_engine(app, db)
        app.register_blueprint(investigation_bp)
    """
    if db_instance is not None:
        global db
        db = db_instance
    with app.app_context():
        db.create_all()
    return investigation_bp