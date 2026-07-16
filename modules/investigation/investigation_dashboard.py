"""
Investigation Summary Dashboard — Phase 5
-------------------------------------------
Deliberately named differently from any existing dashboard.py in this
project so it can NOT collide with or overwrite anything already in
modules/investigation/. Safe to drop in alongside your existing files.

Shows: open cases, risk score breakdown, evidence count, activity
timeline, and a case table — sourced from modules/case_management.py
(create_case, get_case, list_cases, etc.), which is what this project
actually uses for case storage.

ROUTES (both intentionally distinct from your existing /dashboard):
    GET /investigation-summary
    GET /api/investigation-summary/stats

WIRE-UP — add to app.py:

    try:
        from modules.investigation.investigation_dashboard import investigation_dashboard_bp
        _HAS_INVESTIGATION_SUMMARY = True
    except ImportError:
        _HAS_INVESTIGATION_SUMMARY = False

    ...

    if _HAS_INVESTIGATION_SUMMARY:
        app.register_blueprint(investigation_dashboard_bp)

Template expected at:
    templates/investigation/investigation_summary.html
(also a new filename — won't touch any existing dashboard.html)
"""

from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, session, redirect, url_for

try:
    from modules.case_management import list_cases
    _HAS_CASE_MODULE = True
except ImportError:
    _HAS_CASE_MODULE = False

try:
    from modules.investigations.evidence_store import evidence_summary
    _HAS_EVIDENCE_MODULE = True
except ImportError:
    _HAS_EVIDENCE_MODULE = False

# ── CONFIG ───────────────────────────────────────────────────────────────
# Adjust these if your case dicts use different key names.
STATUS_OPEN_VALUES = {"open"}
STATUS_CLOSED_VALUES = {"closed"}

RISK_BANDS = [
    ("critical", 80, 100),
    ("high", 60, 79),
    ("medium", 30, 59),
    ("low", 0, 29),
]

TIMELINE_DAYS = 14

investigation_dashboard_bp = Blueprint(
    "investigation_dashboard",
    __name__,
    template_folder="../../templates/investigation",
)


def _field(case, *names, default=None):
    """Pull a field from a case whether it's a dict or an object."""
    for name in names:
        if isinstance(case, dict) and name in case:
            return case[name]
        if hasattr(case, name):
            return getattr(case, name)
    return default


def _risk_band(case):
    """
    Your cases don't have a numeric risk_score — they have a 'priority'
    field (low/medium/high/critical, sometimes 'urgent'). Map that
    directly instead of hunting for a score that doesn't exist.
    """
    priority = str(_field(case, "priority", default="")).strip().lower()
    if priority in ("critical", "urgent"):
        return "critical"
    if priority == "high":
        return "high"
    if priority == "medium":
        return "medium"
    if priority == "low":
        return "low"
    return "unknown"


_PRIORITY_SCORE = {"critical": 95, "high": 70, "medium": 45, "low": 15}


def _get_stats():
    if not _HAS_CASE_MODULE:
        return _mock_stats()

    try:
        cases = list_cases() or []
    except Exception as e:
        print(f"[investigation_dashboard] list_cases() failed: {e}")
        return _mock_stats()

    total = len(cases)
    open_count = sum(1 for c in cases if str(_field(c, "status", default="")).lower() in STATUS_OPEN_VALUES)
    closed_count = sum(1 for c in cases if str(_field(c, "status", default="")).lower() in STATUS_CLOSED_VALUES)

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    scored = []
    for c in cases:
        band = _risk_band(c)
        risk_counts[band] += 1
        if band in _PRIORITY_SCORE:
            scored.append(_PRIORITY_SCORE[band])

    avg_risk = round(sum(scored) / len(scored), 1) if scored else None

    evidence_total = 0
    if _HAS_EVIDENCE_MODULE:
        for c in cases:
            case_id = _field(c, "id", "case_id")
            if case_id is None:
                continue
            try:
                summary = evidence_summary(case_id)
                if isinstance(summary, dict):
                    evidence_total += (
                        summary.get("count")
                        or summary.get("total")
                        or summary.get("total_count")
                        or summary.get("file_count")
                        or summary.get("total_files")
                        or 0
                    )
                elif isinstance(summary, int):
                    evidence_total += summary
                elif isinstance(summary, list):
                    evidence_total += len(summary)
            except Exception as e:
                print(f"[investigation_dashboard] evidence_summary({case_id}) failed: {e}")

    return {
        "total_cases": total,
        "open_cases": open_count,
        "closed_cases": closed_count,
        "evidence_count": evidence_total,
        "risk_counts": risk_counts,
        "avg_risk_score": avg_risk,
        "cases": cases,
    }


def _get_timeline(days=TIMELINE_DAYS):
    since = datetime.utcnow() - timedelta(days=days)
    buckets = {}
    for i in range(days + 1):
        day = (since + timedelta(days=i)).date().isoformat()
        buckets[day] = {"cases": 0, "evidence": 0}

    if not _HAS_CASE_MODULE:
        return list(buckets.values()), list(buckets.keys())

    try:
        cases = list_cases() or []
    except Exception:
        cases = []

    for c in cases:
        created = _field(c, "created_at", "created")
        if created is None:
            continue
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created)
            except ValueError:
                continue
        day = created.date().isoformat()
        if day in buckets:
            buckets[day]["cases"] += 1

    labels = list(buckets.keys())
    series = list(buckets.values())
    return series, labels


def _mock_stats():
    return {
        "total_cases": 15,
        "open_cases": 6,
        "closed_cases": 9,
        "evidence_count": 142,
        "risk_counts": {"critical": 3, "high": 4, "medium": 5, "low": 3, "unknown": 0},
        "avg_risk_score": 54.2,
        "cases": [],
    }


def _admin_required():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return None


@investigation_dashboard_bp.route("/investigation-summary")
def investigation_summary_view():
    guard = _admin_required()
    if guard:
        return guard
    stats = _get_stats()
    timeline, labels = _get_timeline()
    return render_template(
        "investigation_summary.html",
        stats=stats,
        timeline=timeline,
        timeline_labels=labels,
        admin_user=session.get("admin_user"),
        admin_role=session.get("admin_role"),
    )


@investigation_dashboard_bp.route("/api/investigation-summary/stats")
def investigation_summary_api():
    guard = _admin_required()
    if guard:
        return jsonify({"error": "unauthorized"}), 403
    stats = _get_stats()
    stats.pop("cases", None)
    timeline, labels = _get_timeline()
    return jsonify({
        "stats": stats,
        "timeline": timeline,
        "timeline_labels": labels,
        "generated_at": datetime.utcnow().isoformat(),
    })