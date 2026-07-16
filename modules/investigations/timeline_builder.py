"""
modules/investigation/timeline_builder.py

Timeline Engine — Phase 3 of the Case Management workflow.

Builds a single chronological timeline for a case by pulling from every
source that already exists in the platform:

    - Case row itself           -> "Case Created"
    - CaseNote rows              -> "Note Added"
    - AuditLog rows              -> "Status Changed", "Priority Changed",
                                      "Evidence Uploaded", "Evidence Deleted",
                                      "Case Updated", "Case Deleted", etc.
    - Evidence files on disk     -> "Evidence Added" (fallback if audit log
                                      entry is missing, e.g. legacy uploads)
    - The case's scan_data blob  -> "Scan Started" / "Risk Updated" /
                                      "Breach Detected" etc, derived from
                                      whatever run_osint_scan() captured
                                      (risk_score, timeline, breach, dark)

No new dependencies. Reuses your existing Case / CaseNote / AuditLog models
and the evidence_store module from Phase 2 (optional — degrades gracefully
if Phase 2 isn't installed).
"""

import re
import json
from datetime import datetime

try:
    from zoneinfo import ZoneInfo
    _UTC = ZoneInfo("UTC")
    _IST = ZoneInfo("Asia/Kolkata")
except Exception:
    # zoneinfo/tzdata not available — fall back to a fixed +5:30 offset
    from datetime import timezone, timedelta
    _UTC = timezone.utc
    _IST = timezone(timedelta(hours=5, minutes=30))

from models import db, Case, CaseNote, AuditLog

try:
    from modules.investigations.evidence_store import list_evidence
    _HAS_EVIDENCE = True
except ImportError:
    _HAS_EVIDENCE = False


# ---------------------------------------------------------------------------
# Event type -> (icon, color-class, human label prefix)
# ---------------------------------------------------------------------------
EVENT_STYLES = {
    "case_created":       {"icon": "🗂️", "css": "evt-case",     "label": "Case Created"},
    "case_updated":       {"icon": "✏️", "css": "evt-update",   "label": "Case Updated"},
    "case_deleted":       {"icon": "🗑️", "css": "evt-danger",   "label": "Case Deleted"},
    "note_added":         {"icon": "📝", "css": "evt-note",     "label": "Note Added"},
    "status_changed":     {"icon": "🔄", "css": "evt-update",   "label": "Status Changed"},
    "priority_changed":   {"icon": "⚡", "css": "evt-warn",     "label": "Priority Changed"},
    "evidence_uploaded":  {"icon": "📁", "css": "evt-evidence", "label": "Evidence Uploaded"},
    "evidence_snapshot":  {"icon": "📸", "css": "evt-evidence", "label": "Snapshot Saved"},
    "evidence_deleted":   {"icon": "❌", "css": "evt-danger",   "label": "Evidence Deleted"},
    "scan_started":       {"icon": "🔍", "css": "evt-scan",     "label": "Scan Started"},
    "risk_updated":       {"icon": "⚠️", "css": "evt-risk",     "label": "Risk Score Updated"},
    "breach_detected":    {"icon": "🔓", "css": "evt-danger",   "label": "Breach Detected"},
    "dark_web_flag":      {"icon": "🕸️", "css": "evt-danger",   "label": "Dark Web Mention Flagged"},
    "export":             {"icon": "⬇️", "css": "evt-update",   "label": "Case Exported"},
    "other":              {"icon": "•",  "css": "evt-other",    "label": "Activity"},
}


def _style(event_type):
    return EVENT_STYLES.get(event_type, EVENT_STYLES["other"])


def _fmt(dt):
    """
    Format a datetime for display, converted to Asia/Kolkata (IST).
    All timestamps stored in the DB are naive UTC (datetime.utcnow()),
    so we attach UTC tzinfo first, then convert to IST before formatting.
    """
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_UTC)
        ist_dt = dt.astimezone(_IST)
        return ist_dt.strftime("%Y-%m-%d %H:%M:%S") + " IST"
    return dt or ""


def _sort_key(event):
    return event.get("timestamp_raw") or datetime.min


# ---------------------------------------------------------------------------
# Parse an AuditLog.detail string for a case_id / id reference, to confirm
# this log entry actually belongs to the case we're building a timeline for.
# Detail strings look like: "id=5 target=x", "case_id=5 file=y", etc.
# ---------------------------------------------------------------------------
def _detail_matches_case(detail: str, case_id: int) -> bool:
    if not detail:
        return False
    patterns = [
        rf"\bcase_id={case_id}\b",
        rf"\bid={case_id}\b",
    ]
    return any(re.search(p, detail) for p in patterns)


def _parse_detail(detail: str) -> dict:
    """Extract key=value pairs from an audit detail string for display."""
    if not detail:
        return {}
    return dict(re.findall(r"(\w+)=([^\s]+)", detail))


# ---------------------------------------------------------------------------
# Build events from the Case row
# ---------------------------------------------------------------------------
def _events_from_case(case: Case) -> list:
    events = []
    if case.created_at:
        events.append({
            "type": "case_created",
            "timestamp_raw": case.created_at,
            "timestamp": _fmt(case.created_at),
            "actor": case.created_by or "unknown",
            "detail": f"Case #{case.id} opened for target {case.target}",
        })
    return events


# ---------------------------------------------------------------------------
# Build events from CaseNote rows
# ---------------------------------------------------------------------------
def _events_from_notes(case_id: int) -> list:
    events = []
    try:
        notes = CaseNote.query.filter_by(case_id=case_id).order_by(CaseNote.created_at).all()
    except Exception:
        notes = []
    for n in notes:
        preview = (n.content or "").strip()
        if len(preview) > 140:
            preview = preview[:140].rstrip() + "…"
        events.append({
            "type": "note_added",
            "timestamp_raw": n.created_at,
            "timestamp": _fmt(n.created_at),
            "actor": n.author or "unknown",
            "detail": preview,
        })
    return events


# ---------------------------------------------------------------------------
# Build events from AuditLog rows relevant to this case
# ---------------------------------------------------------------------------
_AUDIT_ACTION_MAP = {
    "created_case":      "case_created",   # covered by case row too; dedup by timestamp below
    "updated_case":      "case_updated",
    "deleted_case":      "case_deleted",
    "added_note":         None,             # covered by CaseNote directly, skip to avoid dupes
    "evidence_uploaded":  "evidence_uploaded",
    "evidence_snapshot":  "evidence_snapshot",
    "evidence_deleted":   "evidence_deleted",
    "exported_report":    "export",
    "exported_case":      "export",
}


def _events_from_audit(case_id: int) -> list:
    events = []
    try:
        logs = AuditLog.query.order_by(AuditLog.timestamp).all()
    except Exception:
        logs = []

    for log in logs:
        if not _detail_matches_case(log.detail or "", case_id):
            continue

        mapped_type = _AUDIT_ACTION_MAP.get(log.action)
        if mapped_type is None:
            continue

        parsed = _parse_detail(log.detail or "")
        detail_text = log.detail or ""

        if mapped_type == "evidence_uploaded" and "file" in parsed:
            detail_text = f"Uploaded {parsed['file']}"
        elif mapped_type == "evidence_deleted" and "file" in parsed:
            detail_text = f"Removed {parsed['file']}"
        elif mapped_type == "case_updated":
            detail_text = "Case fields updated"
        elif mapped_type == "case_deleted":
            detail_text = "Case permanently deleted"
        elif mapped_type == "export":
            detail_text = "Case exported"

        events.append({
            "type": mapped_type,
            "timestamp_raw": log.timestamp,
            "timestamp": _fmt(log.timestamp),
            "actor": log.admin_user or "unknown",
            "detail": detail_text,
        })

    return events


# ---------------------------------------------------------------------------
# Build events from evidence files on disk (fallback for legacy files with
# no matching audit log entry, e.g. manually dropped into the folder)
# ---------------------------------------------------------------------------
def _events_from_evidence_fallback(case_id: int, already_covered_files: set) -> list:
    if not _HAS_EVIDENCE:
        return []
    events = []
    try:
        items = list_evidence(case_id)
    except Exception:
        items = []
    for item in items:
        if item["filename"] in already_covered_files:
            continue
        try:
            ts = datetime.strptime(item["modified_at"], "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue
        events.append({
            "type": "evidence_uploaded",
            "timestamp_raw": ts,
            "timestamp": _fmt(ts),
            "actor": "system",
            "detail": f"{item['filename']} ({item['size_human']})",
        })
    return events


# ---------------------------------------------------------------------------
# Build events derived from the case's stored scan_data blob
#
# scan_data is a single snapshot taken at case-creation time, so there is no
# real per-field timestamp for "when risk was calculated" vs "when breach was
# found" — they all happened inside the same run_osint_scan() call. Showing
# them all at an identical second reads as broken. We stagger them a few
# seconds apart in the order run_osint_scan() actually performs the work
# (scan -> breach check -> dark web check -> risk score, computed last).
# This is a display-ordering aid, not a claim of real elapsed time.
# ---------------------------------------------------------------------------
def _events_from_scan_data(case: Case) -> list:
    events = []
    scan = {}
    try:
        scan = json.loads(case.scan_data or "{}")
    except (TypeError, ValueError):
        return events

    if not scan:
        return events

    from datetime import timedelta
    anchor = case.created_at or datetime.utcnow()
    step = timedelta(seconds=1)
    t = anchor

    if scan.get("target"):
        t = t + step
        events.append({
            "type": "scan_started",
            "timestamp_raw": t,
            "timestamp": _fmt(t),
            "actor": "scanner",
            "detail": f"OSINT scan captured for {scan.get('target')}",
        })

    breach = scan.get("breach")
    if isinstance(breach, list) and len(breach) > 0:
        t = t + step
        events.append({
            "type": "breach_detected",
            "timestamp_raw": t,
            "timestamp": _fmt(t),
            "actor": "leak_checker",
            "detail": f"{len(breach)} breach record(s) found",
        })

    dark = scan.get("dark")
    if isinstance(dark, dict) and dark.get("flagged"):
        t = t + step
        findings = dark.get("findings") or []
        events.append({
            "type": "dark_web_flag",
            "timestamp_raw": t,
            "timestamp": _fmt(t),
            "actor": "dark_monitor",
            "detail": f"{len(findings)} dark web mention(s) flagged",
        })

    risk = scan.get("risk_score")
    if isinstance(risk, dict) and not risk.get("error"):
        t = t + step
        score = risk.get("total_score") or risk.get("score")
        events.append({
            "type": "risk_updated",
            "timestamp_raw": t,
            "timestamp": _fmt(t),
            "actor": "risk_engine",
            "detail": f"Risk score calculated: {score if score is not None else 'n/a'}",
        })

    return events


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def build_case_timeline(case_id: int) -> list:
    """
    Returns a chronologically ordered list of timeline events for a case:

        [
          {
            "type": "case_created",
            "icon": "🗂️",
            "css": "evt-case",
            "label": "Case Created",
            "timestamp": "2026-07-01 10:01:00",
            "actor": "admin",
            "detail": "Case #5 opened for target example.com",
          },
          ...
        ]
    """
    case = Case.query.get(case_id)
    if not case:
        return []

    events = []
    events += _events_from_case(case)
    events += _events_from_notes(case_id)
    events += _events_from_scan_data(case)

    audit_events = _events_from_audit(case_id)
    events += audit_events

    covered_evidence_files = set()
    for e in audit_events:
        if e["type"] in ("evidence_uploaded", "evidence_deleted") and "detail" in e:
            m = re.search(r"(?:Uploaded|Removed) (\S+)", e["detail"])
            if m:
                covered_evidence_files.add(m.group(1))

    events += _events_from_evidence_fallback(case_id, covered_evidence_files)

    # Sort chronologically, oldest first
    events.sort(key=_sort_key)

    # Attach display metadata + sequence numbers
    enriched = []
    for i, e in enumerate(events, start=1):
        style = _style(e["type"])
        enriched.append({
            "seq": i,
            "type": e["type"],
            "icon": style["icon"],
            "css": style["css"],
            "label": style["label"],
            "timestamp": e["timestamp"],
            "actor": e.get("actor", "unknown"),
            "detail": e.get("detail", ""),
        })

    return enriched


def timeline_summary(case_id: int) -> dict:
    """Quick counts for widgets — total events, breakdown by type."""
    events = build_case_timeline(case_id)
    summary = {"total": len(events)}
    for e in events:
        summary[e["type"]] = summary.get(e["type"], 0) + 1
    if events:
        summary["first_event"] = events[0]["timestamp"]
        summary["last_event"] = events[-1]["timestamp"]
    return summary