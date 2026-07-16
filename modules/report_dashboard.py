"""
report_dashboard.py
Analytics, charts, and historical reports for the OSINT platform.
Returns structured data for rendering in Flask templates / Chart.js.
"""

import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import List, Dict, Optional, Any

from models import db

try:
    from models import History, AuditLog
    _HAS_HISTORY = True
except ImportError:
    _HAS_HISTORY = False

try:
    from models import AlertLog
    _HAS_ALERTS = True
except ImportError:
    _HAS_ALERTS = False

try:
    from models import ScheduledTarget
    _HAS_SCHEDULED = True
except ImportError:
    _HAS_SCHEDULED = False

try:
    from models import Case
    _HAS_CASES = True
except ImportError:
    _HAS_CASES = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _daterange(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days)


def _safe_strftime(dt, fmt="%Y-%m-%d %H:%M") -> str:
    """Safely format a datetime, returning empty string if None."""
    if not dt:
        return ""
    if isinstance(dt, str):
        return dt[:16]
    try:
        return dt.strftime(fmt)
    except Exception:
        return str(dt)


# ── Overview Stats ────────────────────────────────────────────────────────────

def get_overview_stats() -> Dict:
    stats = {
        "total_scans":       0,
        "flagged_scans":     0,
        "scans_today":       0,
        "scans_this_week":   0,
        "scans_this_month":  0,
        "unique_targets":    0,
        "total_cases":       0,
        "open_cases":        0,
        "scheduled_targets": 0,
        "alerts_sent":       0,
        "alerts_failed":     0,
    }

    if _HAS_HISTORY:
        try:
            now = datetime.utcnow()
            stats["total_scans"]      = History.query.count()
            stats["flagged_scans"]    = History.query.filter_by(flagged=True).count()
            stats["scans_today"]      = History.query.filter(
                History.scanned_at >= now.replace(hour=0, minute=0, second=0, microsecond=0)
            ).count()
            stats["scans_this_week"]  = History.query.filter(History.scanned_at >= _daterange(7)).count()
            stats["scans_this_month"] = History.query.filter(History.scanned_at >= _daterange(30)).count()
            targets = [h.target for h in History.query.with_entities(History.target).all()]
            stats["unique_targets"]   = len(set(targets))
        except Exception as e:
            print(f"[report_dashboard/history] {e}")

    if _HAS_CASES:
        try:
            stats["total_cases"] = Case.query.count()
            stats["open_cases"]  = Case.query.filter_by(status="open").count()
        except Exception:
            pass

    if _HAS_SCHEDULED:
        try:
            stats["scheduled_targets"] = ScheduledTarget.query.filter_by(enabled=True).count()
        except Exception:
            pass

    if _HAS_ALERTS:
        try:
            stats["alerts_sent"]   = AlertLog.query.filter_by(success=True).count()
            stats["alerts_failed"] = AlertLog.query.filter_by(success=False).count()
        except Exception:
            pass

    return stats


# ── Scan Trend ────────────────────────────────────────────────────────────────

def get_scan_trend(days: int = 30) -> Dict:
    labels, counts = [], []
    if not _HAS_HISTORY:
        return {"labels": [], "counts": []}
    for i in range(days - 1, -1, -1):
        day   = datetime.utcnow() - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end   = start + timedelta(days=1)
        try:
            count = History.query.filter(
                History.scanned_at >= start,
                History.scanned_at < end,
            ).count()
        except Exception:
            count = 0
        labels.append(day.strftime("%b %d"))
        counts.append(count)
    return {"labels": labels, "counts": counts}


def get_flagged_trend(days: int = 30) -> Dict:
    labels, counts = [], []
    if not _HAS_HISTORY:
        return {"labels": [], "counts": []}
    for i in range(days - 1, -1, -1):
        day   = datetime.utcnow() - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end   = start + timedelta(days=1)
        try:
            count = History.query.filter(
                History.scanned_at >= start,
                History.scanned_at < end,
                History.flagged == True,
            ).count()
        except Exception:
            count = 0
        labels.append(day.strftime("%b %d"))
        counts.append(count)
    return {"labels": labels, "counts": counts}


def get_top_targets(limit: int = 10) -> List[Dict]:
    """Most frequently scanned targets — returns list of dicts."""
    if not _HAS_HISTORY:
        return []
    try:
        rows   = History.query.with_entities(History.target).all()
        counts = Counter(r.target for r in rows)
        return [
            {
                "target":  target,
                "count":   count,
                "flagged": _target_ever_flagged(target),
            }
            for target, count in counts.most_common(limit)
        ]
    except Exception as e:
        print(f"[report_dashboard/top_targets] {e}")
        return []


def _target_ever_flagged(target: str) -> bool:
    try:
        return bool(History.query.filter_by(target=target, flagged=True).first())
    except Exception:
        return False


def get_scan_type_distribution() -> Dict:
    if not _HAS_HISTORY:
        return {}
    try:
        rows   = History.query.with_entities(History.scan_type).all()
        counts = Counter(r.scan_type or "full" for r in rows)
        return dict(counts)
    except Exception as e:
        print(f"[report_dashboard/scan_type] {e}")
        return {}


def get_hourly_distribution() -> Dict:
    if not _HAS_HISTORY:
        return {"labels": [f"{h:02d}:00" for h in range(24)], "counts": [0] * 24}
    try:
        since = _daterange(30)
        rows  = History.query.filter(History.scanned_at >= since).with_entities(History.scanned_at).all()
        hour_counts = [0] * 24
        for row in rows:
            if row.scanned_at and not isinstance(row.scanned_at, str):
                hour_counts[row.scanned_at.hour] += 1
        return {"labels": [f"{h:02d}:00" for h in range(24)], "counts": hour_counts}
    except Exception as e:
        print(f"[report_dashboard/hourly] {e}")
        return {"labels": [], "counts": []}


# ── Case / Alert Analytics ────────────────────────────────────────────────────

def get_case_stats() -> Dict:
    if not _HAS_CASES:
        return {}
    try:
        cases           = Case.query.all()
        status_counts   = Counter(c.status   or "open"   for c in cases)
        priority_counts = Counter(c.priority or "medium" for c in cases)
        return {
            "by_status":   dict(status_counts),
            "by_priority": dict(priority_counts),
            "total":       len(cases),
        }
    except Exception as e:
        print(f"[report_dashboard/case_stats] {e}")
        return {}


def get_alert_stats(days: int = 30) -> Dict:
    if not _HAS_ALERTS:
        return {}
    try:
        since       = _daterange(days)
        logs        = AlertLog.query.filter(AlertLog.sent_at >= since).all()
        type_counts = Counter(l.alert_type for l in logs)
        sev_counts  = Counter(l.severity   for l in logs)
        return {
            "total":       len(logs),
            "successful":  sum(1 for l in logs if l.success),
            "failed":      sum(1 for l in logs if not l.success),
            "by_type":     dict(type_counts),
            "by_severity": dict(sev_counts),
        }
    except Exception as e:
        print(f"[report_dashboard/alert_stats] {e}")
        return {}


# ── Main Report Builder ───────────────────────────────────────────────────────

def build_historical_report(days: int = 30) -> Dict:
    """
    Build a comprehensive historical report for the last N days.

    The returned dict uses FLAT keys so templates can access them directly:
        report.total_scans
        report.trend_labels / trend_counts / trend_flagged
        report.top_targets          ← list of {target, count, flagged}
        report.recent_scans         ← list of dicts with string scanned_at
        report.daily_breakdown      ← list of {date, count, flagged}
    """
    trend       = get_scan_trend(days)
    flagged_tr  = get_flagged_trend(days)
    top_targets = get_top_targets(10)
    overview    = get_overview_stats()

    report = {
        # Meta
        "period":    f"Last {days} days",
        "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),

        # Flat stat keys used directly in the template
        "total_scans":    0,
        "flagged_count":  0,
        "unique_targets": 0,
        "breach_count":   0,
        "avg_per_day":    0,

        # Chart data (flat lists)
        "trend_labels":  trend.get("labels", []),
        "trend_counts":  trend.get("counts", []),
        "trend_flagged": flagged_tr.get("counts", []),

        # Top targets as list of dicts
        "top_targets": top_targets,

        # Tables
        "recent_scans":    [],
        "daily_breakdown": [],

        # Extra analytics
        "scan_type_distribution": get_scan_type_distribution(),
        "hourly_distribution":    get_hourly_distribution(),
        "case_stats":             get_case_stats(),
        "alert_stats":            get_alert_stats(days),
        "recent_alerts":          [],
        "scheduled_overview":     [],
    }

    # Fill flat stats from overview
    if _HAS_HISTORY:
        try:
            since  = _daterange(days)
            period_scans   = History.query.filter(History.scanned_at >= since).all()
            period_flagged = sum(1 for s in period_scans if s.flagged)
            unique_targets = len(set(s.target for s in period_scans))

            report["total_scans"]    = len(period_scans)
            report["flagged_count"]  = period_flagged
            report["unique_targets"] = unique_targets
            report["breach_count"]   = 0          # extend if you track breaches in History
            report["avg_per_day"]    = round(len(period_scans) / max(days, 1), 1)
        except Exception as e:
            print(f"[report_dashboard/flat_stats] {e}")

    # Recent scans — scanned_at stored as a string so template never calls .strftime()
    if _HAS_HISTORY:
        try:
            since = _daterange(days)
            scans = (
                History.query
                .filter(History.scanned_at >= since)
                .order_by(History.id.desc())
                .limit(20)
                .all()
            )
            report["recent_scans"] = [
                {
                    "id":        s.id,
                    "target":    s.target,
                    "flagged":   s.flagged,
                    "scan_type": s.scan_type or "full",
                    "scanned_at": _safe_strftime(s.scanned_at),
                }
                for s in scans
            ]
        except Exception as e:
            print(f"[report_dashboard/recent_scans] {e}")

    # Daily breakdown table — one row per day
    if _HAS_HISTORY:
        try:
            daily = []
            for i in range(days - 1, -1, -1):
                day   = datetime.utcnow() - timedelta(days=i)
                start = day.replace(hour=0, minute=0, second=0, microsecond=0)
                end   = start + timedelta(days=1)
                total   = History.query.filter(History.scanned_at >= start, History.scanned_at < end).count()
                flagged = History.query.filter(
                    History.scanned_at >= start,
                    History.scanned_at < end,
                    History.flagged == True,
                ).count()
                daily.append({
                    "date":    day.strftime("%Y-%m-%d"),
                    "count":   total,
                    "flagged": flagged,
                })
            report["daily_breakdown"] = daily
        except Exception as e:
            print(f"[report_dashboard/daily_breakdown] {e}")

    # Recent alerts
    if _HAS_ALERTS:
        try:
            since  = _daterange(days)
            alerts = (
                AlertLog.query
                .filter(AlertLog.sent_at >= since)
                .order_by(AlertLog.id.desc())
                .limit(10)
                .all()
            )
            report["recent_alerts"] = [
                {
                    "id":         a.id,
                    "target":     a.target,
                    "alert_type": a.alert_type,
                    "severity":   a.severity,
                    "success":    a.success,
                    "sent_at":    _safe_strftime(a.sent_at),
                }
                for a in alerts
            ]
        except Exception as e:
            print(f"[report_dashboard/recent_alerts] {e}")

    # Scheduled targets
    if _HAS_SCHEDULED:
        try:
            targets = ScheduledTarget.query.filter_by(enabled=True).all()
            report["scheduled_overview"] = [
                {
                    "target":          t.target,
                    "frequency":       t.frequency,
                    "last_run":        _safe_strftime(t.last_run) or "Never",
                    "change_detected": t.change_detected or False,
                    "run_count":       t.run_count or 0,
                }
                for t in targets
            ]
        except Exception as e:
            print(f"[report_dashboard/scheduled] {e}")

    return report


# ── Export ────────────────────────────────────────────────────────────────────

def export_report_json(days: int = 30) -> str:
    report = build_historical_report(days)
    return json.dumps(report, indent=2, default=str)


def get_target_history(target: str) -> Dict:
    if not _HAS_HISTORY:
        return {}
    try:
        rows = History.query.filter_by(target=target).order_by(History.id.desc()).all()
        return {
            "target":        target,
            "total_scans":   len(rows),
            "flagged_count": sum(1 for r in rows if r.flagged),
            "first_seen":    _safe_strftime(rows[-1].scanned_at, "%Y-%m-%d") if rows else None,
            "last_seen":     _safe_strftime(rows[0].scanned_at,  "%Y-%m-%d") if rows else None,
            "scans": [
                {
                    "id":        r.id,
                    "flagged":   r.flagged,
                    "scan_type": r.scan_type or "full",
                    "scanned_at": _safe_strftime(r.scanned_at),
                }
                for r in rows
            ],
        }
    except Exception as e:
        print(f"[report_dashboard/target_history] {e}")
        return {}