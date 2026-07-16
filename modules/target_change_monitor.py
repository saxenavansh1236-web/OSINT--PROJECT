"""
target_change_monitor.py — Phase 7: Automatic Change Detection
------------------------------------------------------------------
Sits ON TOP OF your existing modules — doesn't touch alert_engine.py
or scheduled_scan.py. It:

  1. Stores a snapshot of each scan result per target (flat JSON files,
     no new DB table required).
  2. On the next scan of the same target, diffs the new result against
     the stored snapshot.
  3. If anything meaningful changed (IP, subdomains, DNS, SSL issuer,
     tech stack, breach count, dark-web flags...), it calls your
     existing alert_engine.send_change_alert(...) so notifications go
     out through the SMTP/webhook config you already have.

WATCH TARGETS / AUTO SCAN:
Those already exist in modules/scheduled_scan.py (add_target, list_targets,
run_now, init_scheduler). This module doesn't duplicate that — it hooks
INTO the scan function you pass to init_scheduler, so every scheduled
run gets change detection for free.

NOTE ON DOUBLE-ALERTING:
scheduled_scan.py ALREADY does its own hash-based change detection and
already calls send_change_alert(st.target, st.notify_email, result) in
_execute_scan(). If you also wrap the scan function passed to
init_scheduler() with monitored_scan(), scheduled targets will be
diffed and alerted on TWICE (once by scheduled_scan.py's hash compare,
once by this module's field-level diff) — using two different
detection methods. That's not necessarily wrong (this module's diff is
more granular — it tells you WHAT changed, not just THAT something
changed) but you may end up with two separate emails per real change.

Recommended usage to avoid duplicate emails:
  - Use monitored_scan() for the MANUAL "/" scan only (home()), where
    scheduled_scan.py never runs and there's no other alert path.
  - For scheduled targets, let scheduled_scan.py's own alerting stay
    authoritative and skip wrapping with monitored_scan() — OR pass
    notify_email=None to check_and_alert() there so this module logs/
    diffs but doesn't also email.

WIRE-UP (app.py):

    from modules.target_change_monitor import check_and_alert

    # manual scan, inside home():
    result = run_osint_scan(target)
    changes = check_and_alert(target, result, notify_email=None)
    result["_changes"] = changes

That's the only touch point needed in app.py. alert_engine.py and
scheduled_scan.py stay exactly as they are.
"""

import os
import json
import hashlib
from datetime import datetime, timezone

SNAPSHOT_DIR = os.environ.get("CHANGE_MONITOR_DIR", "monitor_snapshots")
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

# ── Fields we consider "meaningful" to diff on. Adjust freely. ─────────────


def _safe_get(d, *path, default=None):
    cur = d
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return default
    return cur if cur is not None else default


def _subdomain_set(result):
    subs = result.get("subs") or []
    out = set()
    for s in subs:
        out.add(s if isinstance(s, str) else s.get("host", str(s)))
    return out


def _breach_names(result):
    breaches = result.get("breach") or []
    out = set()
    for b in breaches:
        if isinstance(b, dict):
            out.add(b.get("name") or b.get("breach_name") or "unknown")
        else:
            out.add(str(b))
    return out


WATCHED_FIELDS = {
    "ip": lambda r: r.get("ip"),
    "geo_country": lambda r: _safe_get(r, "geo", "country"),
    "ssl_issuer": lambda r: _safe_get(r, "ssl", "issuer_o"),
    "dark_flagged": lambda r: _safe_get(r, "dark", "flagged", default=False),
    "cloud_provider": lambda r: _safe_get(r, "cloud", "primary_provider"),
}

WATCHED_SET_FIELDS = {
    "subdomains": _subdomain_set,
    "breaches": _breach_names,
}


# ── Snapshot storage ─────────────────────────────────────────────────────

def _snapshot_path(target):
    safe = hashlib.sha256(target.encode("utf-8")).hexdigest()[:24]
    return os.path.join(SNAPSHOT_DIR, f"{safe}.json")


def _extract_comparable(result):
    """Reduce a full scan result down to just the fields we diff on."""
    out = {}
    for key, fn in WATCHED_FIELDS.items():
        try:
            out[key] = fn(result)
        except Exception:
            out[key] = None
    for key, fn in WATCHED_SET_FIELDS.items():
        try:
            out[key] = sorted(fn(result))
        except Exception:
            out[key] = []
    return out


def get_last_snapshot(target):
    path = _snapshot_path(target)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[target_change_monitor] failed to read snapshot for {target}: {e}")
        return None


def save_snapshot(target, result):
    path = _snapshot_path(target)
    payload = {
        "target": target,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "data": _extract_comparable(result),
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except Exception as e:
        print(f"[target_change_monitor] failed to save snapshot for {target}: {e}")


# ── Diffing ──────────────────────────────────────────────────────────────

def diff_snapshots(old_data, new_data):
    """
    Returns a list of change dicts:
        {"field": "ip", "old": "1.2.3.4", "new": "5.6.7.8"}
        {"field": "subdomains", "added": [...], "removed": [...]}
    """
    changes = []

    for field in WATCHED_FIELDS:
        old_val = old_data.get(field)
        new_val = new_data.get(field)
        if old_val != new_val:
            changes.append({"field": field, "old": old_val, "new": new_val})

    for field in WATCHED_SET_FIELDS:
        old_set = set(old_data.get(field, []))
        new_set = set(new_data.get(field, []))
        added = sorted(new_set - old_set)
        removed = sorted(old_set - new_set)
        if added or removed:
            changes.append({"field": field, "added": added, "removed": removed})

    return changes


def format_changes_text(target, changes):
    lines = [f"Changes detected for {target}:"]
    for c in changes:
        if "old" in c:
            lines.append(f"  - {c['field']}: {c['old']!r} -> {c['new']!r}")
        else:
            if c.get("added"):
                lines.append(f"  - {c['field']} added: {', '.join(c['added'])}")
            if c.get("removed"):
                lines.append(f"  - {c['field']} removed: {', '.join(c['removed'])}")
    return "\n".join(lines)


# ── Alert dispatch (uses your existing alert_engine, unmodified) ──────────

def _dispatch_alert(target, changes, result, notify_email=None):
    """
    Calls alert_engine.send_change_alert(target, to_email, result) — the
    REAL signature (confirmed from alert_engine.py) takes the full scan
    result dict, since it reads risk_score / breach / dark / ip off of
    it to build the email. `changes` is only used here to build the
    printed/logged summary when there's no recipient to email.
    """
    try:
        from modules.alert_engine import send_change_alert, get_smtp_config_public
    except ImportError:
        print("[target_change_monitor] alert_engine not available, skipping alert")
        return False

    to_email = notify_email
    if not to_email:
        try:
            cfg = get_smtp_config_public()
            to_email = cfg.get("user") if isinstance(cfg, dict) else None
        except Exception:
            to_email = None

    if not to_email:
        print(f"[target_change_monitor] no recipient email for {target}, skipping alert send "
              f"(changes were still detected)")
        print(format_changes_text(target, changes))
        return False

    try:
        send_change_alert(target, to_email, result)
        return True
    except Exception as e:
        print(f"[target_change_monitor] send_change_alert failed: {e}")
        return False


# ── Public API ───────────────────────────────────────────────────────────

def check_and_alert(target, result, notify_email=None):
    """
    Compares `result` (a fresh scan) against the last stored snapshot
    for `target`. If there's a prior snapshot and something changed,
    fires an alert via alert_engine and returns the list of changes.
    Always saves the new snapshot at the end (so the next scan diffs
    against this one).

    notify_email: pass the target's own notify_email (from
    ScheduledTarget) if this is a scheduled scan, or leave None for
    manual scans — in that case it falls back to the configured SMTP
    account address (probably not what you want for scheduled
    per-target alerts, see module docstring on double-alerting).

    Returns: list of change dicts (empty if no prior snapshot or no changes)
    """
    previous = get_last_snapshot(target)
    new_data = _extract_comparable(result)

    changes = []
    if previous is not None:
        changes = diff_snapshots(previous.get("data", {}), new_data)
        if changes:
            print(f"[target_change_monitor] {len(changes)} change(s) detected for {target}")
            _dispatch_alert(target, changes, result, notify_email=notify_email)

    save_snapshot(target, result)
    return changes


def monitored_scan(scan_fn):
    """
    Wraps a scan function (e.g. run_osint_scan) so every call also runs
    change detection afterward. See module docstring — recommended for
    the manual "/" scan only, NOT for scheduled targets (scheduled_scan.py
    already has its own change detection + alerting for those).
    """
    def wrapped(target, *args, **kwargs):
        result = scan_fn(target, *args, **kwargs)
        try:
            result["_changes"] = check_and_alert(target, result)
        except Exception as e:
            print(f"[target_change_monitor] check_and_alert failed for {target}: {e}")
        return result
    return wrapped