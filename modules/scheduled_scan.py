"""
scheduled_scan.py
Daily/periodic monitoring of targets with change detection.
Uses APScheduler (lightweight, no Redis required).

Install: pip install apscheduler
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    _HAS_SCHEDULER = True
except ImportError:
    _HAS_SCHEDULER = False
    print("[scheduled_scan] APScheduler not installed. Run: pip install apscheduler")

from models import db

# ── SQLAlchemy Model — add to models.py ──────────────────────────────────────
#
# class ScheduledTarget(db.Model):
#     __tablename__ = "scheduled_targets"
#     id             = db.Column(db.Integer, primary_key=True)
#     target         = db.Column(db.String(500), nullable=False)
#     label          = db.Column(db.String(200), default="")
#     frequency      = db.Column(db.String(50), default="daily")   # daily/weekly/hourly
#     enabled        = db.Column(db.Boolean, default=True)
#     last_run       = db.Column(db.DateTime, nullable=True)
#     last_hash      = db.Column(db.String(64), default="")        # SHA256 of last result
#     change_detected= db.Column(db.Boolean, default=False)
#     run_count      = db.Column(db.Integer, default=0)
#     created_at     = db.Column(db.DateTime, default=datetime.utcnow)
#     notify_email   = db.Column(db.String(200), default="")
#
# ─────────────────────────────────────────────────────────────────────────────

try:
    from models import ScheduledTarget
    _HAS_MODEL = True
except ImportError:
    _HAS_MODEL = False

# Global scheduler instance
_scheduler: Optional[object] = None
_scan_fn: Optional[Callable] = None   # Injected by app.py


def init_scheduler(app, scan_function: Callable):
    """
    Initialise the background scheduler.
    Call this once from app.py after db.init_app(app).

    Example in app.py:
        from modules.scheduled_scan import init_scheduler
        from modules.scheduled_scan import init_scheduler
        with app.app_context():
            db.create_all()
            init_scheduler(app, run_osint_scan)
    """
    global _scheduler, _scan_fn

    if not _HAS_SCHEDULER:
        print("[scheduled_scan] Cannot start — APScheduler not installed.")
        return

    _scan_fn = scan_function

    _scheduler = BackgroundScheduler(timezone="UTC")

    # Master job: every hour, check which targets are due
    _scheduler.add_job(
        func=lambda: _run_due_targets(app),
        trigger=IntervalTrigger(hours=1),
        id="master_scheduler",
        replace_existing=True,
        name="OSINT Master Scheduler",
    )

    # Also run once at startup (after 60 s delay)
    _scheduler.add_job(
        func=lambda: _run_due_targets(app),
        trigger=IntervalTrigger(seconds=60, end_date=datetime.utcnow() + timedelta(seconds=120)),
        id="startup_run",
        replace_existing=True,
        name="Startup scan check",
    )

    _scheduler.start()
    print("[scheduled_scan] Background scheduler started.")


def _run_due_targets(app):
    """Check all enabled scheduled targets and run those that are due."""
    if not _HAS_MODEL or not _scan_fn:
        return

    with app.app_context():
        targets = ScheduledTarget.query.filter_by(enabled=True).all()
        now = datetime.utcnow()

        for st in targets:
            if _is_due(st, now):
                _execute_scan(st, app)


def _is_due(st, now: datetime) -> bool:
    """Return True if the scheduled target should run now."""
    if st.last_run is None:
        return True

    freq = (st.frequency or "daily").lower()
    delta_map = {
        "hourly": timedelta(hours=1),
        "daily":  timedelta(days=1),
        "weekly": timedelta(weeks=1),
    }
    delta = delta_map.get(freq, timedelta(days=1))
    return now >= st.last_run + delta


def _result_hash(result: dict) -> str:
    """Compute a stable hash of a scan result for change detection."""
    key_fields = {
        "ip": result.get("ip"),
        "breach_count": len(result.get("breach") or []),
        "subs_count": len(result.get("subs") or []),
        "whois_registrar": (result.get("whois") or {}).get("registrar"),
        "ssl_expiry": (result.get("ssl") or {}).get("not_after"),
        "dark_flagged": (result.get("dark") or {}).get("flagged"),
        "risk_score": (result.get("risk_score") or {}).get("total_score"),
        "open_ports": len((result.get("port_scan") or {}).get("open_ports") or []),
    }
    serialised = json.dumps(key_fields, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()


def _execute_scan(st, app):
    """Run a scan for a scheduled target and update the DB record."""
    from modules.alert_engine import send_change_alert  # lazy import to avoid circular
    try:
        print(f"[scheduled_scan] Running scan for: {st.target}")
        result = _scan_fn(st.target)
        new_hash = _result_hash(result)

        change_detected = bool(st.last_hash and st.last_hash != new_hash)

        st.last_run = datetime.utcnow()
        st.last_hash = new_hash
        st.change_detected = change_detected
        st.run_count = (st.run_count or 0) + 1
        db.session.commit()

        if change_detected and st.notify_email:
            try:
                send_change_alert(st.target, st.notify_email, result)
            except Exception as e:
                print(f"[scheduled_scan] Alert error: {e}")

        print(f"[scheduled_scan] Done: {st.target} | change={change_detected}")

    except Exception as e:
        print(f"[scheduled_scan] Error scanning {st.target}: {e}")
        db.session.rollback()


# ── Public API ────────────────────────────────────────────────────────────────

def add_target(target: str, label: str = "", frequency: str = "daily",
               notify_email: str = "") -> Optional[int]:
    """Add a target to the scheduled scan list."""
    if not _HAS_MODEL:
        raise RuntimeError("ScheduledTarget model not in models.py")
    try:
        existing = ScheduledTarget.query.filter_by(target=target).first()
        if existing:
            existing.enabled = True
            existing.frequency = frequency
            existing.label = label or existing.label
            existing.notify_email = notify_email or existing.notify_email
            db.session.commit()
            return existing.id

        st = ScheduledTarget(
            target=target,
            label=label or target,
            frequency=frequency,
            notify_email=notify_email,
        )
        db.session.add(st)
        db.session.commit()
        return st.id
    except Exception as e:
        db.session.rollback()
        print(f"[scheduled_scan/add] {e}")
        return None


def remove_target(target_id: int) -> bool:
    """Remove a scheduled target."""
    if not _HAS_MODEL:
        return False
    try:
        st = ScheduledTarget.query.get(target_id)
        if st:
            db.session.delete(st)
            db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[scheduled_scan/remove] {e}")
        return False


def toggle_target(target_id: int, enabled: bool) -> bool:
    """Enable or disable a scheduled target."""
    if not _HAS_MODEL:
        return False
    try:
        st = ScheduledTarget.query.get(target_id)
        if not st:
            return False
        st.enabled = enabled
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return False


def list_targets() -> List[Dict]:
    """List all scheduled targets."""
    if not _HAS_MODEL:
        return []
    try:
        targets = ScheduledTarget.query.order_by(ScheduledTarget.id).all()
        return [
            {
                "id": t.id,
                "target": t.target,
                "label": t.label or t.target,
                "frequency": t.frequency or "daily",
                "enabled": t.enabled,
                "last_run": t.last_run.strftime("%Y-%m-%d %H:%M:%S") if t.last_run else "Never",
                "next_run": _next_run_str(t),
                "run_count": t.run_count or 0,
                "change_detected": t.change_detected or False,
                "notify_email": t.notify_email or "",
            }
            for t in targets
        ]
    except Exception as e:
        print(f"[scheduled_scan/list] {e}")
        return []


def _next_run_str(st) -> str:
    if not st.enabled:
        return "Disabled"
    if not st.last_run:
        return "Pending"
    freq = (st.frequency or "daily").lower()
    delta_map = {"hourly": timedelta(hours=1), "daily": timedelta(days=1), "weekly": timedelta(weeks=1)}
    delta = delta_map.get(freq, timedelta(days=1))
    next_run = st.last_run + delta
    return next_run.strftime("%Y-%m-%d %H:%M:%S")


def run_now(target_id: int, app) -> bool:
    """Immediately trigger a scan for a scheduled target."""
    if not _HAS_MODEL:
        return False
    try:
        st = ScheduledTarget.query.get(target_id)
        if not st or not _scan_fn:
            return False
        _execute_scan(st, app)
        return True
    except Exception as e:
        print(f"[scheduled_scan/run_now] {e}")
        return False


def shutdown():
    """Shutdown the background scheduler gracefully."""
    global _scheduler
    if _scheduler and _HAS_SCHEDULER:
        try:
            _scheduler.shutdown(wait=False)
            print("[scheduled_scan] Scheduler stopped.")
        except Exception:
            pass