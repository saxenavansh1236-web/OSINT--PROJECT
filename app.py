import os
from dotenv import load_dotenv
load_dotenv()
import re
import csv
import io
import subprocess
import uuid
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from collections import Counter

from flask import (
    Flask, render_template, request, send_file,
    session, flash, abort, jsonify, redirect, url_for, Response,
    send_from_directory,
)
from modules.intelligence.confidence_score import analyze_case
from modules.intelligence.case_similarity import find_similar_cases, summarize_notes
from werkzeug.security import generate_password_hash
from modules.investigations.evidence_store import (
    store_file, store_text, store_json, list_evidence,
    get_evidence_path, delete_evidence, snapshot_case, evidence_summary,
)
from modules.investigations.timeline_builder import build_case_timeline, timeline_summary
from modules.case_report_generator import generate_case_report

from security.rate_limiter import limiter, apply_limits, scan_limit, login_limit, api_limit, export_limit, sensitive_limit
from security.sql_protection import register_sqli_guard, sanitise_target, SQLiDetected
from security.captcha import captcha_html, verify_captcha
from security.jwt_auth import auth_bp, jwt_required, jwt_role_required

from modules.username import search_username
from modules.whois_lookup import whois_data
from modules.subdomain import get_subdomains
from modules.reverse_ip import reverse_lookup
from modules.leak_checker import check_email as breach_check
from modules.geo import locate, resolve_ip
from modules.report import export_report, export_historical_pdf
from modules.dark_monitor import monitor

try:
    from modules.scheduled_scan import init_scheduler
    _HAS_SCHEDULED = True
except Exception:
    _HAS_SCHEDULED = False

from modules.target_change_monitor import monitored_scan, check_and_alert
from models import db, History, User, AuditLog

try:
    from modules.investigation.investigation_dashboard import investigation_dashboard_bp
    _HAS_INVESTIGATION_SUMMARY = True
except ImportError:
    _HAS_INVESTIGATION_SUMMARY = False

try:
    from modules.identity_score import score as identity_score
    _HAS_IDENTITY = True
except ImportError:
    _HAS_IDENTITY = False

try:
    from modules.dns_lookup import lookup as dns_lookup
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

try:
    from modules.ssl_info import inspect as ssl_inspect
    _HAS_SSL = True
except ImportError:
    _HAS_SSL = False

try:
    from modules.tech_stake import detect as tech_detect
    _HAS_TECH = True
except ImportError:
    _HAS_TECH = False

try:
    from modules.email import investigate as email_investigate
    _HAS_EMAIL = True
except ImportError:
    _HAS_EMAIL = False

try:
    from modules.archive_lookup import lookup as archive_lookup
    _HAS_ARCHIVE = True
except ImportError:
    _HAS_ARCHIVE = False

try:
    from modules.phone_lookup import lookup as phone_lookup
    _HAS_PHONE = True
except ImportError:
    _HAS_PHONE = False

try:
    from modules.leak_checker import check_all as leak_check_all
    _HAS_LEAK = True
except ImportError:
    _HAS_LEAK = False

try:
    from modules.screenshot import capture as screenshot_capture
    _HAS_SCREENSHOT = True
except ImportError:
    _HAS_SCREENSHOT = False

try:
    from modules.port_scan import scan as port_scan
    _HAS_PORT_SCAN = True
except ImportError:
    _HAS_PORT_SCAN = False

try:
    from modules.headers_analysis import inspect as headers_inspect
    _HAS_HEADERS = True
except ImportError:
    _HAS_HEADERS = False

try:
    from modules.employee_lookup import lookup as employee_lookup
    _HAS_EMPLOYEE = True
except ImportError:
    _HAS_EMPLOYEE = False

try:
    from modules.timeline import build as timeline_build
    _HAS_TIMELINE = True
except ImportError:
    _HAS_TIMELINE = False

try:
    from modules.risk_score import calculate as risk_calculate
    _HAS_RISK = True
except ImportError:
    _HAS_RISK = False

try:
    from modules.robots_scan import scan as robots_scan
    _HAS_ROBOTS = True
except ImportError:
    _HAS_ROBOTS = False

try:
    from modules.certificate_history import lookup as cert_history_lookup
    _HAS_CERT_HISTORY = True
except ImportError:
    _HAS_CERT_HISTORY = False

try:
    from modules.directory_discovery import discover as dir_discover
    _HAS_DIR = True
except ImportError:
    _HAS_DIR = False

try:
    from modules.paste_monitor import monitor as paste_monitor
    _HAS_PASTE = True
except ImportError:
    _HAS_PASTE = False

try:
    from modules.cloud_detector import detect as cloud_detect
    _HAS_CLOUD = True
except ImportError:
    _HAS_CLOUD = False

try:
    from modules.virustotal import lookup as vt_lookup
    _HAS_VT = True
except ImportError:
    _HAS_VT = False

try:
    from modules.abuse_lookup import lookup as abuse_lookup
    _HAS_ABUSE = True
except ImportError:
    _HAS_ABUSE = False

try:
    from modules.urlscan_lookup import lookup as urlscan_lookup
    _HAS_URLSCAN = True
except ImportError:
    _HAS_URLSCAN = False

try:
    from modules.dork_generator import generate as dork_generate
    _HAS_DORKS = True
except ImportError:
    _HAS_DORKS = False

try:
    from modules.otx_lookup import lookup as otx_lookup
    _HAS_OTX = True
except ImportError:
    _HAS_OTX = False

try:
    from modules.report_dashboard import (
        build_historical_report, get_overview_stats,
        get_scan_trend, get_top_targets, export_report_json,
        get_target_history,
    )
    _HAS_REPORT_DASH = True
except ImportError:
    _HAS_REPORT_DASH = False

try:
    from modules.alert_engine import (
        send_change_alert, send_breach_alert,
        get_alert_logs, save_smtp_config, get_smtp_config_public,
    )
    _HAS_ALERTS = True
except ImportError:
    _HAS_ALERTS = False

try:
    from modules.case_management import (
        create_case, get_case, list_cases, update_case,
        delete_case, add_note, get_notes, export_case,
    )
    _HAS_CASES = True
except ImportError:
    _HAS_CASES = False

try:
    from modules.scheduled_scan import (
        add_target as sched_add, remove_target as sched_remove,
        toggle_target as sched_toggle, list_targets as sched_list,
        run_now as sched_run_now, init_scheduler, shutdown as sched_shutdown,
    )
    _HAS_SCHEDULED = True
except ImportError:
    _HAS_SCHEDULED = False

try:
    _HAS_INTELLIGENCE = True
except ImportError:
    _HAS_INTELLIGENCE = False

# ── NEW FEATURE MODULES ──────────────────────────────────────────────────
try:
    from modules.investigation_summary import build_summary
    _HAS_AI_SUMMARY = True
except ImportError:
    _HAS_AI_SUMMARY = False

try:
    from modules.related_entities import build_related_entities
    _HAS_RELATED_ENTITIES = True
except ImportError:
    _HAS_RELATED_ENTITIES = False

try:
    from modules.ioc_export import build_ioc, to_stix, to_misp
    _HAS_IOC_EXPORT = True
except ImportError:
    _HAS_IOC_EXPORT = False

try:
    from modules.social_search_links import build_social_and_mentions
    _HAS_SOCIAL_LINKS = True
except ImportError:
    _HAS_SOCIAL_LINKS = False

try:
    from modules.entity_graph import build_entity_graph
    _HAS_ENTITY_GRAPH = True
except ImportError:
    _HAS_ENTITY_GRAPH = False

try:
    from modules.cross_case_correlation import correlate_cases
    _HAS_CROSS_CASE = True
except ImportError:
    _HAS_CROSS_CASE = False

try:
    from modules.image_intel.image_hashing import compute_hashes
    _HAS_IMG_HASH = True
except ImportError:
    _HAS_IMG_HASH = False

try:
    from modules.image_intel.duplicate_detection import check_and_index
    _HAS_DUPLICATE = True
except ImportError:
    _HAS_DUPLICATE = False

try:
    from modules.image_intel.qr_barcode import scan as qr_scan
    _HAS_QR = True
except ImportError:
    _HAS_QR = False

try:
    from modules.image_intel.ocr_extract import extract_text as ocr_extract_text
    _HAS_OCR = True
except ImportError:
    _HAS_OCR = False

try:
    from modules.image_intel.object_detection import detect as object_detect
    _HAS_OBJECT_DETECTION = True
except ImportError:
    _HAS_OBJECT_DETECTION = False

try:
    from modules.image_intel.face_detection import detect as face_detect
    _HAS_FACE_DETECTION = True
except ImportError:
    _HAS_FACE_DETECTION = False

try:
    from modules.image_intel.landmark_detection import detect as landmark_detect
    _HAS_LANDMARK = True
except ImportError:
    _HAS_LANDMARK = False

try:
    from modules.image_intel.reverse_image_search import build_links as build_reverse_search_links
    _HAS_REVERSE_SEARCH = True
except ImportError:
    _HAS_REVERSE_SEARCH = False

# ── NEW IMAGE INTELLIGENCE MODULES (GPS, risk, quality, forgery, etc.) ──
try:
    from modules.image_intel.gps_extraction import extract as gps_extract
    _HAS_GPS = True
except ImportError:
    _HAS_GPS = False

try:
    from modules.image_intel.metadata_risk import assess as metadata_risk_assess
    _HAS_METADATA_RISK = True
except ImportError:
    _HAS_METADATA_RISK = False

try:
    from modules.image_intel.caption import caption as ai_caption
    _HAS_CAPTION = True
except ImportError:
    _HAS_CAPTION = False

try:
    from modules.image_intel.ai_generated_detection import detect as ai_generated_detect
    _HAS_AI_GENERATED = True
except ImportError:
    _HAS_AI_GENERATED = False

try:
    from modules.image_intel.forgery_detection import analyze as forgery_analyze
    _HAS_FORGERY = True
except ImportError:
    _HAS_FORGERY = False

try:
    from modules.image_intel.face_attributes import analyze as face_attrs_analyze
    _HAS_FACE_ATTRS = True
except ImportError:
    _HAS_FACE_ATTRS = False

try:
    from modules.image_intel.image_quality import analyze as quality_analyze
    _HAS_QUALITY = True
except ImportError:
    _HAS_QUALITY = False

try:
    from modules.image_intel.color_palette import extract as color_palette_extract
    _HAS_COLOR_PALETTE = True
except ImportError:
    _HAS_COLOR_PALETTE = False

try:
    from modules.image_intel.logo_detection import detect as logo_detect
    _HAS_LOGOS = True
except ImportError:
    _HAS_LOGOS = False

try:
    from modules.image_intel.vehicle_detection import detect as vehicle_detect
    _HAS_VEHICLE = True
except ImportError:
    _HAS_VEHICLE = False

try:
    from modules.image_intel.license_plate_ocr import detect as plate_detect
    _HAS_PLATE = True
except ImportError:
    _HAS_PLATE = False

try:
    from modules.image_intel.similarity_search import search as similarity_search
    _HAS_SIMILARITY = True
except ImportError:
    _HAS_SIMILARITY = False

# ==========================
# APP SETUP
# ==========================

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///database.db")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

apply_limits(app)
register_sqli_guard(app)
app.register_blueprint(auth_bp)
if _HAS_INVESTIGATION_SUMMARY:
    app.register_blueprint(investigation_dashboard_bp)

# ──────────────────────────────────────────────────────────────────────────
# FIX: create the database tables at import time, not just under
# `if __name__ == "__main__":`. Production servers (gunicorn, Render, etc.)
# import this module as `app:app` and never execute the __main__ block, so
# db.create_all() previously never ran in production — causing
# "sqlalchemy.exc.OperationalError: no such table: user" on /register,
# /login, and anywhere else the User/History/AuditLog tables are queried.
#
# db.create_all() is idempotent (it only creates tables that don't already
# exist), so it's always safe to call here on every startup.
# ──────────────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()

_SCHEDULER_STARTED = False


def _start_scheduler_once():
    """Start the background scheduler exactly once, regardless of whether
    the app is launched via `python app.py` or a WSGI server like gunicorn."""
    global _SCHEDULER_STARTED
    if _SCHEDULER_STARTED:
        return
    if _HAS_SCHEDULED:
        try:
            init_scheduler(app, monitored_scan(run_osint_scan))
            _SCHEDULER_STARTED = True
        except NameError:
            # run_osint_scan not yet defined at this point in the module —
            # scheduler will be started later from __main__ instead.
            pass
        except Exception as e:
            print(f"[Scheduler Init Error] {e}")


UPLOAD_FOLDER = "uploads"
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp", "tiff", "bmp", "heic"}
MAX_IMAGE_SIZE_MB = 15

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def _allowed_image(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS
    )


def _exiftool_available() -> bool:
    from shutil import which
    return which("exiftool") is not None


_security_events = {
    "sqli_blocked":      0,
    "captcha_failed":    0,
    "captcha_passed":    0,
    "rate_limited":      0,
    "jwt_rejected":      0,
    "jwt_accepted":      0,
    "login_failed":      0,
    "login_success":     0,
}


def _sec_inc(key: str):
    _security_events[key] = _security_events.get(key, 0) + 1


_scan_cache: dict[str, dict] = {}
_CACHE_MAX = 50


def _cache_put(target: str, result: dict):
    if target in _scan_cache:
        del _scan_cache[target]
    _scan_cache[target] = result
    if len(_scan_cache) > _CACHE_MAX:
        oldest = next(iter(_scan_cache))
        del _scan_cache[oldest]


def _cache_get(target: str) -> dict:
    return _scan_cache.get(target, {})


def _to_dict(obj):
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(i) for i in obj]
    if hasattr(obj, "to_dict"):
        return _to_dict(obj.to_dict())
    try:
        import dataclasses
        if dataclasses.is_dataclass(obj):
            return _to_dict(dataclasses.asdict(obj))
    except Exception:
        pass
    if hasattr(obj, "_asdict"):
        return _to_dict(obj._asdict())
    if hasattr(obj, "__dict__"):
        return _to_dict(vars(obj))
    return str(obj)


def _serialise_result(result: dict) -> dict:
    serialised = {}
    for key, value in result.items():
        serialised[key] = _to_dict(value)

    breach_list = serialised.get("breach")
    if isinstance(breach_list, list):
        clean = []
        for b in breach_list:
            if isinstance(b, dict):
                if "breach_name" in b and "name" not in b:
                    b["name"] = b["breach_name"]
                clean.append(b)
            else:
                s = str(b)
                clean.append({"name": s, "severity": "high", "source": "?"})
        serialised["breach"] = clean

    uname_list = serialised.get("username")
    if isinstance(uname_list, list):
        clean = []
        for u in uname_list:
            if isinstance(u, dict):
                clean.append(u)
            elif isinstance(u, str):
                clean.append({"name": u, "url": "", "category": "Other"})
            else:
                clean.append({"name": str(u), "url": "", "category": "Other"})
        serialised["username"] = clean

    return serialised


def validate_target(target: str) -> tuple[bool, str]:
    if not target:
        return False, "Target cannot be empty."
    if len(target) > 253:
        return False, "Target is too long."
    forbidden = [";", "&", "|", "`", "$", "<", ">"]
    if any(ch in target for ch in forbidden):
        return False, "Target contains invalid characters."
    return True, ""


def _is_email(target: str) -> bool:
    return "@" in target and "." in target.split("@")[-1]


def _is_phone(target: str) -> bool:
    cleaned = re.sub(r"[\s\-().]+", "", target)
    return bool(re.match(r"^\+?\d{7,15}$", cleaned))


def _is_domain(target: str) -> bool:
    return "." in target and not _is_email(target) and not _is_phone(target)


def _is_ip(target: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))


def admin_required():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return None


def role_required(required_role: str):
    roles = {"admin": 3, "analyst": 2, "viewer": 1}
    user_role = session.get("admin_role", "viewer")
    if roles.get(user_role, 0) < roles.get(required_role, 99):
        flash("You don't have permission to do that.", "error")
        return redirect(url_for("dashboard"))
    return None


def write_audit(action: str, detail: str = ""):
    try:
        log = AuditLog(
            admin_user=session.get("admin_user") or session.get("username") or "unknown",
            action=action,
            detail=detail,
            ip_address=request.remote_addr or "",
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"[Audit Error] {e}")


# ==========================
# PUBLIC USER AUTH (scanner access)
# ==========================
# Separate from the admin session (`session["admin"]`). This gate protects
# the public scanner (`/`) and Image OSINT (`/image-osint`) pages so only
# registered accounts can run scans. Admins still log in separately at
# `/admin` and are unaffected by this system.

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to use the scanner.", "error")
            return redirect(url_for("user_login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


@app.route("/register", methods=["GET", "POST"])
@login_limit
def user_register():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        ok, msg = verify_captcha(request)
        if not ok:
            _sec_inc("captcha_failed")
            flash(msg, "error")
            return render_template("register.html", captcha=captcha_html())
        _sec_inc("captcha_passed")

        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html", captcha=captcha_html())

        if len(username) > 80:
            flash("Username is too long.", "error")
            return render_template("register.html", captcha=captcha_html())

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html", captcha=captcha_html())

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html", captcha=captcha_html())

        if User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
            return render_template("register.html", captcha=captcha_html())

        try:
            user = User(username=username, role="user", is_active=True)
            if hasattr(user, "email"):
                user.email = email
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"[Register Error] {e}")
            flash("Could not create account. Please try again.", "error")
            return render_template("register.html", captcha=captcha_html())

        write_audit("user_registered", f"username={username}")
        flash("Account created. Please log in.", "success")
        return redirect(url_for("user_login"))

    return render_template("register.html", captcha=captcha_html())


@app.route("/login", methods=["GET", "POST"])
@login_limit
def user_login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    next_url = request.args.get("next") or url_for("home")

    if request.method == "POST":
        ok, msg = verify_captcha(request)
        if not ok:
            _sec_inc("captcha_failed")
            flash(msg, "error")
            return render_template("login.html", captcha=captcha_html(), next=next_url)
        _sec_inc("captcha_passed")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        posted_next = request.form.get("next") or next_url

        user = User.query.filter_by(username=username, is_active=True).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            _sec_inc("login_success")
            write_audit("user_login", f"username={username}")
            return redirect(posted_next)

        _sec_inc("login_failed")
        write_audit("user_login_failed", f"attempted_user={username}")
        flash("Invalid username or password.", "error")

    return render_template("login.html", captcha=captcha_html(), next=next_url)


@app.route("/logout-user")
def user_logout():
    write_audit("user_logout", f"username={session.get('username','')}")
    session.pop("user_id", None)
    session.pop("username", None)
    return redirect(url_for("user_login"))


# ==========================
# SCAN
# ==========================

def run_osint_scan(target: str) -> dict:
    result    = {"target": target}
    is_email  = _is_email(target)
    is_phone  = _is_phone(target)
    is_domain = _is_domain(target)
    is_ip     = _is_ip(target)

    print(f"[scan] target={target!r}  is_email={is_email}  is_phone={is_phone}  is_domain={is_domain}  is_ip={is_ip}")

    try:
        result["username"] = search_username(target)
    except Exception as e:
        result["username"] = []
        print(f"[username] {e}")

    try:
        leak_report = breach_check(target)
        result["breach"] = leak_report.leaks
    except Exception as e:
        result["breach"] = []
        print(f"[breach] {e}")

    try:
        result["dark"] = monitor(target)
        if not isinstance(result["dark"], dict):
            result["dark"] = {"flagged": False, "findings": [], "error": None}
    except Exception as e:
        result["dark"] = {"flagged": False, "findings": [], "error": str(e)}
        print(f"[dark] {e}")

    if _HAS_PASTE:
        try:
            pm = paste_monitor(target)
            result["paste_monitor"] = pm.to_dict() if hasattr(pm, "to_dict") else pm
        except Exception as e:
            result["paste_monitor"] = {"error": str(e)}

    if _HAS_VT:
        try:
            vt = vt_lookup(target)
            result["virustotal"] = vt.to_dict() if hasattr(vt, "to_dict") else vt
        except Exception as e:
            result["virustotal"] = {"error": str(e)}

    if _HAS_DORKS:
        try:
            dorks = dork_generate(target)
            dork_obj = dorks.to_dict() if hasattr(dorks, "to_dict") else dorks
            result["dorks"] = dork_obj.get("dorks", []) if isinstance(dork_obj, dict) else dorks
        except Exception as e:
            result["dorks"] = []

    if is_domain:
        try:
            result["whois"] = whois_data(target)
        except Exception as e:
            result["whois"] = {"error": str(e)}

        try:
            result["subs"] = get_subdomains(target)
        except Exception as e:
            result["subs"] = []

        try:
            ip = reverse_lookup(target) or resolve_ip(target)
            result["ip"]  = ip or "Not found"
            result["geo"] = locate(ip or target) if (ip or target) else {}
        except Exception as e:
            result["ip"]  = "Not found"
            result["geo"] = {"error": str(e)}

        if _HAS_DNS:
            try:
                dns = dns_lookup(target)
                result["dns"] = dns.to_dict() if hasattr(dns, "to_dict") else dns
            except Exception as e:
                result["dns"] = {"error": str(e)}

        if _HAS_SSL:
            try:
                ssl = ssl_inspect(target)
                result["ssl"] = ssl.to_dict() if hasattr(ssl, "to_dict") else ssl
            except Exception as e:
                result["ssl"] = {"error": str(e)}

        if _HAS_TECH:
            try:
                tech = tech_detect(target)
                result["tech"] = tech.to_dict() if hasattr(tech, "to_dict") else tech
            except Exception as e:
                result["tech"] = {"error": str(e)}

        if _HAS_ARCHIVE:
            try:
                archive = archive_lookup(target, max_snapshots=200)
                result["archive"] = archive.to_dict() if hasattr(archive, "to_dict") else archive
            except Exception as e:
                result["archive"] = {"error": str(e)}

        if _HAS_SCREENSHOT:
            try:
                shot = screenshot_capture(target, export_pdf=False, watermark=True)
                result["screenshot"] = shot.to_dict() if hasattr(shot, "to_dict") else shot
            except Exception as e:
                result["screenshot"] = {"error": str(e)}

        if _HAS_LEAK:
            try:
                leak = leak_check_all(target, "domain")
                result["leak"] = leak.to_dict() if hasattr(leak, "to_dict") else leak
            except Exception as e:
                result["leak"] = {"error": str(e)}

        if _HAS_PORT_SCAN:
            try:
                ps = port_scan(target, mode="common")
                result["port_scan"] = ps.to_dict() if hasattr(ps, "to_dict") else ps
            except Exception as e:
                result["port_scan"] = {"error": str(e)}

        if _HAS_HEADERS:
            try:
                ha = headers_inspect(target)
                result["headers_analysis"] = ha.to_dict() if hasattr(ha, "to_dict") else ha
            except Exception as e:
                result["headers_analysis"] = {"error": str(e)}

        if _HAS_EMPLOYEE:
            try:
                emp = employee_lookup(target)
                result["employee"] = emp.to_dict() if hasattr(emp, "to_dict") else emp
            except Exception as e:
                result["employee"] = {"error": str(e)}

        if _HAS_ROBOTS:
            try:
                rb = robots_scan(target)
                result["robots"] = rb.to_dict() if hasattr(rb, "to_dict") else rb
            except Exception as e:
                result["robots"] = {"error": str(e)}

        if _HAS_CERT_HISTORY:
            try:
                ch = cert_history_lookup(target)
                result["cert_history"] = ch.to_dict() if hasattr(ch, "to_dict") else ch
            except Exception as e:
                result["cert_history"] = {"error": str(e)}

        if _HAS_DIR:
            try:
                dd = dir_discover(target)
                result["directory_discovery"] = dd.to_dict() if hasattr(dd, "to_dict") else dd
            except Exception as e:
                result["directory_discovery"] = {"error": str(e)}

        if _HAS_CLOUD:
            try:
                cd = cloud_detect(target)
                result["cloud"] = cd.to_dict() if hasattr(cd, "to_dict") else cd
            except Exception as e:
                result["cloud"] = {"error": str(e)}

        if _HAS_ABUSE:
            try:
                abuse = abuse_lookup(target)
                result["abuse"] = abuse.to_dict() if hasattr(abuse, "to_dict") else abuse
            except Exception as e:
                result["abuse"] = {"error": str(e)}

        if _HAS_URLSCAN:
            try:
                us = urlscan_lookup(target)
                result["urlscan"] = us.to_dict() if hasattr(us, "to_dict") else us
            except Exception as e:
                result["urlscan"] = {"error": str(e)}

        if _HAS_OTX:
            try:
                otx = otx_lookup(target)
                result["otx"] = otx.to_dict() if hasattr(otx, "to_dict") else otx
            except Exception as e:
                result["otx"] = {"error": str(e)}

    if is_ip:
        try:
            result["geo"] = locate(target)
        except Exception as e:
            result["geo"] = {"error": str(e)}

        if _HAS_ABUSE:
            try:
                abuse = abuse_lookup(target)
                result["abuse"] = abuse.to_dict() if hasattr(abuse, "to_dict") else abuse
            except Exception as e:
                result["abuse"] = {"error": str(e)}

        if _HAS_OTX:
            try:
                otx = otx_lookup(target)
                result["otx"] = otx.to_dict() if hasattr(otx, "to_dict") else otx
            except Exception as e:
                result["otx"] = {"error": str(e)}

    if is_email:
        if _HAS_EMAIL:
            try:
                email_result = email_investigate(target, check_breaches=True)
                result["email_osint"] = (
                    email_result.to_dict() if hasattr(email_result, "to_dict") else email_result
                )
                if not result.get("breach") and hasattr(email_result, "breaches"):
                    result["breach"] = email_result.breaches
            except Exception as e:
                result["email_osint"] = {"error": str(e)}

        domain_part = target.split("@")[-1]
        if _HAS_DNS:
            try:
                dns = dns_lookup(domain_part)
                result["dns"] = dns.to_dict() if hasattr(dns, "to_dict") else dns
            except Exception as e:
                result["dns"] = {"error": str(e)}

        if _HAS_LEAK:
            try:
                leak = leak_check_all(target, "email")
                result["leak"] = leak.to_dict() if hasattr(leak, "to_dict") else leak
            except Exception as e:
                result["leak"] = {"error": str(e)}

    if is_phone:
        if _HAS_PHONE:
            try:
                phone = phone_lookup(target)
                result["phone"] = phone.to_dict() if hasattr(phone, "to_dict") else phone
            except Exception as e:
                result["phone"] = {"error": str(e)}

        if _HAS_LEAK:
            try:
                leak = leak_check_all(target, "phone")
                result["leak"] = leak.to_dict() if hasattr(leak, "to_dict") else leak
            except Exception as e:
                result["leak"] = {"error": str(e)}

    if not is_domain and not is_email and not is_phone and not is_ip and _HAS_PHONE:
        try:
            phone = phone_lookup(target)
            if phone.valid:
                result["phone"] = phone.to_dict() if hasattr(phone, "to_dict") else phone
        except Exception:
            pass

    if not is_domain and not is_email and not is_phone and not is_ip:
        if _HAS_LEAK:
            try:
                leak = leak_check_all(target, "username")
                result["leak"] = leak.to_dict() if hasattr(leak, "to_dict") else leak
            except Exception as e:
                result["leak"] = {"error": str(e)}

    result = _serialise_result(result)

    if _HAS_TIMELINE:
        try:
            tl = timeline_build(target, result)
            result["timeline"] = tl.to_dict() if hasattr(tl, "to_dict") else _to_dict(tl)
        except Exception as e:
            result["timeline"] = {"error": str(e)}

    if _HAS_RISK:
        try:
            rs = risk_calculate(target, result)
            result["risk_score"] = rs.to_dict() if hasattr(rs, "to_dict") else _to_dict(rs)
        except Exception as e:
            result["risk_score"] = {"error": str(e)}

    if _HAS_IDENTITY:
        try:
            result["identity_score"] = identity_score(result)
        except Exception as e:
            result["identity_score"] = {"error": str(e)}

    # ── NEW FEATURES ──────────────────────────────────────────────────────
    if _HAS_RELATED_ENTITIES:
        try:
            case_lookup = None
            if _HAS_CASES:
                case_lookup = lambda t: [
                    {"id": c.get("id"), "title": c.get("title"), "status": c.get("status")}
                    for c in list_cases(search=t)
                ]
            entities = build_related_entities(result, case_lookup=case_lookup)
            result["related_entities"] = entities.to_dict()
        except Exception as e:
            result["related_entities"] = {"error": str(e)}

    if _HAS_SOCIAL_LINKS:
        try:
            result["social_mentions"] = build_social_and_mentions(target)
        except Exception as e:
            result["social_mentions"] = {"error": str(e)}

    if _HAS_ENTITY_GRAPH:
        try:
            result["entity_graph"] = build_entity_graph(target, result)
        except Exception as e:
            result["entity_graph"] = {"error": str(e)}

    if _HAS_CROSS_CASE and _HAS_CASES:
        try:
            all_cases = list_cases()
            result["cross_case_correlation"] = correlate_cases(target, result, all_cases)
        except Exception as e:
            result["cross_case_correlation"] = {"error": str(e)}

    if _HAS_AI_SUMMARY:
        try:
            summary = build_summary(target, result)
            result["ai_summary"] = summary.to_dict()
        except Exception as e:
            result["ai_summary"] = {"error": str(e)}

    if _HAS_IOC_EXPORT:
        try:
            ioc = build_ioc(target, result)
            result["ioc"] = ioc.to_dict()
        except Exception as e:
            result["ioc"] = {"error": str(e)}

    return result


# Now that run_osint_scan exists, it's safe to (re)try starting the
# scheduler if it wasn't already started above.
_start_scheduler_once()


# ==========================
# IOC EXPORT ROUTES
# ==========================

@app.route("/export/ioc/stix")
@export_limit
def export_ioc_stix():
    if not _HAS_IOC_EXPORT:
        abort(404)
    target = session.get("latest_target", "")
    latest = _cache_get(target) if target else {}
    if not latest:
        flash("Run a scan first.", "error")
        abort(400)
    from modules.ioc_export import build_ioc, to_stix
    ioc = build_ioc(target, latest)
    stix_json = to_stix(ioc)
    return Response(
        stix_json, mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=ioc_{target}_stix.json"},
    )


@app.route("/export/ioc/misp")
@export_limit
def export_ioc_misp():
    if not _HAS_IOC_EXPORT:
        abort(404)
    from modules.ioc_export import build_ioc, to_misp
    target = session.get("latest_target", "")
    latest = _cache_get(target) if target else {}
    if not latest:
        flash("Run a scan first.", "error")
        abort(400)
    ioc = build_ioc(target, latest)
    misp_json = to_misp(ioc)
    return Response(
        misp_json, mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=ioc_{target}_misp.json"},
    )


# ==========================
# ENTITY GRAPH ROUTE
# ==========================

@app.route("/entity-graph")
def entity_graph_route():
    if not _HAS_ENTITY_GRAPH:
        return jsonify({"nodes": [], "links": []})
    target = request.args.get("target", "").strip() or session.get("latest_target", "")
    latest = _cache_get(target) if target else {}
    if not latest:
        return jsonify({"nodes": [], "links": []})
    return jsonify(latest.get("entity_graph", {"nodes": [], "links": []}))


@app.route("/cases/<int:case_id>/report")
@export_limit
def case_report_pdf(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case = get_case(case_id)
    if not case:
        abort(404)
    pdf_path = os.path.join(app.root_path, f"case_{case_id}_report.pdf")
    try:
        generate_case_report(case_id, output_path=pdf_path)
    except Exception as e:
        print(f"[Case Report Error] {e}")
        abort(500)
    write_audit("exported_case_report", f"case_id={case_id}")
    return send_file(
        pdf_path, as_attachment=True,
        download_name=f"CASE_{case_id}_REPORT.pdf",
        mimetype="application/pdf",
    )


# ==========================
# HOME (scanner — requires login)
# ==========================

@app.route("/", methods=["GET", "POST"])
@scan_limit
@login_required
def home():
    result = {}
    changes = []
    if request.method == "POST":
        ok, captcha_msg = verify_captcha(request)
        if not ok:
            _sec_inc("captcha_failed")
            flash(captcha_msg, "error")
            return render_template("index.html", result={}, captcha=captcha_html())
        _sec_inc("captcha_passed")

        target = request.form.get("target", "").strip()

        try:
            target = sanitise_target(target)
        except (ValueError, SQLiDetected) as e:
            _sec_inc("sqli_blocked")
            flash(str(e), "error")
            return render_template("index.html", result={}, captcha=captcha_html())

        valid, msg = validate_target(target)
        if not valid:
            flash(msg, "error")
            return render_template("index.html", result={}, captcha=captcha_html())

        flagged = False
        try:
            result = run_osint_scan(target)
            session["latest_target"] = target
            _cache_put(target, result)
            flagged = result.get("dark", {}).get("flagged", False)

            changes = check_and_alert(target, result)
            result["_changes"] = changes

            if _HAS_ALERTS and result.get("breach") and len(result["breach"]) > 0:
                try:
                    cfg = get_smtp_config_public()
                    if cfg.get("configured") and cfg.get("user"):
                        send_breach_alert(target, cfg["user"], result["breach"])
                except Exception:
                    pass

        except Exception as e:
            result = {"error": str(e), "target": target}
            print(f"[Scan Error] {e}")

        try:
            db.session.add(History(target=target, flagged=flagged))
            db.session.commit()
        except Exception as e:
            print(f"[History Error] {e}")
            db.session.rollback()

    return render_template("index.html", result=result, changes=changes, captcha=captcha_html())


@app.route("/history")
def history():
    try:
        data = History.query.order_by(History.id.desc()).all()
    except Exception as e:
        print(f"[History Error] {e}")
        data = []

    # ── Image OSINT scans (logged to AuditLog, not History) ──────────────
    image_scans = []
    try:
        logs = (
            AuditLog.query.filter_by(action="image_osint_scan")
            .order_by(AuditLog.id.desc())
            .limit(200)
            .all()
        )
        for log in logs:
            detail = log.detail or ""
            filename = detail.replace("file=", "").strip() if "file=" in detail else (detail or "unknown")

            # AuditLog's timestamp column name can vary by schema — try the
            # common options in order rather than assuming one exact name.
            scanned_at = None
            for attr in ("timestamp", "created_at", "logged_at", "created", "ts"):
                if hasattr(log, attr):
                    scanned_at = getattr(log, attr)
                    if scanned_at:
                        break

            image_scans.append({
                "filename": filename or "unknown",
                "scanned_at": scanned_at,
            })
    except Exception as e:
        print(f"[Image History Error] {e}")
        image_scans = []

    return render_template("history.html", data=data, image_scans=image_scans)


@app.route("/export")
@export_limit
def export():
    latest_target = session.get("latest_target")
    latest = _cache_get(latest_target) if latest_target else {}
    if not latest:
        flash("Run a scan first.", "error")
        abort(400)
    report_path = os.path.join(app.root_path, "report.pdf")
    try:
        export_report(latest, output_path=report_path)
    except Exception as e:
        print(f"[Export Error] {e}")
        abort(500)
    if not os.path.exists(report_path):
        abort(500)
    return send_file(
        report_path, as_attachment=True,
        download_name=f"osint_report_{latest.get('target', 'unknown')}.pdf",
        mimetype="application/pdf",
    )


@app.route("/admin/reports/export-pdf")
@export_limit
def export_historical_pdf_route():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_REPORT_DASH:
        abort(404)
    days        = int(request.args.get("days", 30))
    report_data = build_historical_report(days)
    pdf_path    = os.path.join(app.root_path, "historical_report.pdf")
    try:
        export_historical_pdf(report_data, output_path=pdf_path)
    except Exception as e:
        print(f"[Historical PDF Error] {e}")
        abort(500)
    write_audit("exported_historical_pdf", f"days={days}")
    return send_file(
        pdf_path, as_attachment=True,
        download_name=f"osint_historical_{days}d.pdf",
        mimetype="application/pdf",
    )


@app.route("/api/result")
@api_limit
@jwt_required
def api_result():
    _sec_inc("jwt_accepted")
    target = request.args.get("target") or session.get("latest_target", "")
    latest = _cache_get(target) if target else {}
    return jsonify(latest)


@app.route("/api/security-stats")
@api_limit
def api_security_stats():
    guard = admin_required()
    if guard:
        return jsonify({"error": "unauthorized"}), 403

    rl_stats = {"status": "active", "note": "counters reset on restart"}
    try:
        rl_stats["backend"] = str(type(limiter._storage).__name__)
    except Exception:
        pass

    try:
        failed_logins = AuditLog.query.filter_by(action="failed_login").count()
        successful_logins = AuditLog.query.filter_by(action="login").count()
    except Exception:
        failed_logins = _security_events["login_failed"]
        successful_logins = _security_events["login_success"]

    return jsonify({
        "rate_limiting": {
            "active": True,
            "rules": {
                "scan":      "10/minute, 100/day",
                "login":     "5/minute, 20/hour",
                "api":       "60/minute",
                "export":    "10/hour",
                "sensitive": "3/minute, 10/hour",
            },
            "total_limited": _security_events["rate_limited"],
            **rl_stats,
        },
        "sql_protection": {
            "active": True,
            "mode":   "before_request hook (all routes)",
            "blocked": _security_events["sqli_blocked"],
        },
        "captcha": {
            "active": True,
            "passed": _security_events["captcha_passed"],
            "failed": _security_events["captcha_failed"],
            "total":  _security_events["captcha_passed"] + _security_events["captcha_failed"],
        },
        "jwt_auth": {
            "active":   True,
            "routes":   ["/api/result", "/api/dashboard-stats", "/api/target-history"],
            "accepted": _security_events["jwt_accepted"],
            "rejected": _security_events["jwt_rejected"],
        },
        "login_guard": {
            "failed":    failed_logins,
            "succeeded": successful_logins,
        },
    })


@app.route("/graph")
def graph():
    requested_target = request.args.get("target", "").strip()
    if not requested_target:
        requested_target = session.get("latest_target", "")

    latest = _cache_get(requested_target) if requested_target else {}
    target = latest.get("target", "")

    if not target:
        return jsonify({"nodes": [], "links": [], "target": requested_target})

    nodes, links = [], []
    nodes.append({"id": target, "type": "target"})

    ip = latest.get("ip")
    if ip and ip != "Not found":
        nodes.append({"id": ip, "type": "ip"})
        links.append({"source": target, "target": ip})
        geo = latest.get("geo", {})
        if isinstance(geo, dict):
            geo_label = geo.get("city") or geo.get("country") or ""
            if geo_label:
                nodes.append({"id": geo_label, "type": "geo"})
                links.append({"source": ip, "target": geo_label})

    for s in (latest.get("subs") or [])[:30]:
        sub_id = s if isinstance(s, str) else s.get("host", str(s))
        nodes.append({"id": sub_id, "type": "subdomain"})
        links.append({"source": target, "target": sub_id})

    for b in (latest.get("breach") or [])[:10]:
        if isinstance(b, dict):
            b_id = b.get("name") or b.get("breach_name") or "Unknown breach"
        else:
            b_id = str(b)
        if b_id:
            nodes.append({"id": b_id, "type": "breach"})
            links.append({"source": target, "target": b_id})

    for u in (latest.get("username") or [])[:10]:
        if isinstance(u, dict):
            u_id = u.get("name") or u.get("url") or str(u)
        else:
            u_id = str(u)
        if u_id:
            nodes.append({"id": u_id, "type": "username"})
            links.append({"source": target, "target": u_id})

    dns = latest.get("dns", {})
    if isinstance(dns, dict):
        for ns in (dns.get("ns") or [])[:5]:
            nodes.append({"id": ns, "type": "dns_ns"})
            links.append({"source": target, "target": ns})
        for mx in (dns.get("mx") or [])[:3]:
            mx_host = mx.get("host", str(mx)) if isinstance(mx, dict) else str(mx)
            nodes.append({"id": mx_host, "type": "dns_mx"})
            links.append({"source": target, "target": mx_host})

    tech = latest.get("tech", {})
    if isinstance(tech, dict):
        for cat in ("cms", "cdn", "framework"):
            for item in (tech.get(cat) or [])[:2]:
                nodes.append({"id": item, "type": "tech"})
                links.append({"source": target, "target": item})

    ssl = latest.get("ssl", {})
    if isinstance(ssl, dict) and ssl.get("issuer_o"):
        nodes.append({"id": ssl["issuer_o"], "type": "ssl"})
        links.append({"source": target, "target": ssl["issuer_o"]})

    dark = latest.get("dark", {})
    if isinstance(dark, dict):
        for f in (dark.get("findings") or [])[:5]:
            if isinstance(f, dict):
                label = f.get("malware") or f.get("threat_type") or f.get("threat") or ""
                if label and "error" not in f:
                    node_id = f"⚠ {label}"
                    nodes.append({"id": node_id, "type": "threat"})
                    links.append({"source": target, "target": node_id})

    port_scan_data = latest.get("port_scan", {})
    if isinstance(port_scan_data, dict):
        for rp in (port_scan_data.get("risky_ports") or [])[:5]:
            if isinstance(rp, dict):
                label = f"Port {rp.get('port')}/{rp.get('service', '?')}"
                nodes.append({"id": label, "type": "threat"})
                links.append({"source": target, "target": label})

    cert_hist = latest.get("cert_history", {})
    if isinstance(cert_hist, dict):
        for issuer in (cert_hist.get("issuers") or [])[:3]:
            nodes.append({"id": f"CA: {issuer}", "type": "ssl"})
            links.append({"source": target, "target": f"CA: {issuer}"})

    cloud = latest.get("cloud", {})
    if isinstance(cloud, dict) and cloud.get("primary_provider") and \
            cloud["primary_provider"] != "Unknown / Self-hosted":
        nodes.append({"id": cloud["primary_provider"], "type": "tech"})
        links.append({"source": target, "target": cloud["primary_provider"]})

    paste = latest.get("paste_monitor", {})
    if isinstance(paste, dict):
        for m in (paste.get("mentions") or [])[:3]:
            if isinstance(m, dict) and m.get("severity") in ("critical", "high"):
                node_id = f"🔴 Paste: {m.get('source', '?')}"
                nodes.append({"id": node_id, "type": "threat"})
                links.append({"source": target, "target": node_id})

    dd = latest.get("directory_discovery", {})
    if isinstance(dd, dict):
        for p in (dd.get("sensitive_found") or [])[:4]:
            if isinstance(p, dict):
                node_id = f"📂 {p.get('path', '?')}"
                nodes.append({"id": node_id, "type": "threat"})
                links.append({"source": target, "target": node_id})

    phone = latest.get("phone", {})
    if isinstance(phone, dict) and phone.get("valid"):
        ph_label = phone.get("international") or phone.get("e164") or "Phone"
        nodes.append({"id": ph_label, "type": "geo"})
        links.append({"source": target, "target": ph_label})
        if phone.get("region"):
            nodes.append({"id": phone["region"], "type": "geo"})
            links.append({"source": ph_label, "target": phone["region"]})

    vt = latest.get("virustotal", {})
    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        for name in (vt.get("threat_names") or [])[:3]:
            nodes.append({"id": f"🦠 {name}", "type": "threat"})
            links.append({"source": target, "target": f"🦠 {name}"})

    otx = latest.get("otx", {})
    if isinstance(otx, dict) and otx.get("pulse_count", 0) > 0:
        for mf in (otx.get("malware_families") or [])[:3]:
            nodes.append({"id": f"⚡ {mf}", "type": "threat"})
            links.append({"source": target, "target": f"⚡ {mf}"})

    return jsonify({"nodes": nodes, "links": links, "target": target})


@app.route("/threat")
def threat():
    target = session.get("latest_target", "")
    latest = _cache_get(target) if target else {}
    return jsonify(latest.get("dark", {}))


@app.route("/admin", methods=["GET", "POST"])
@login_limit
def admin_login():
    if session.get("admin"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        ok, msg = verify_captcha(request)
        if not ok:
            _sec_inc("captcha_failed")
            flash(msg, "error")
            return render_template("admin_login.html", captcha=captcha_html())

        _sec_inc("captcha_passed")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username, is_active=True).first()

        if user and user.check_password(password) and user.role in ("admin", "analyst", "viewer"):
            session["admin"] = True
            session["admin_user"] = username
            session["admin_role"] = user.role
            _sec_inc("login_success")
            write_audit("login", f"user={username} role={user.role}")
            return redirect(url_for("dashboard"))

        _sec_inc("login_failed")
        write_audit("failed_login", f"attempted_user={username}")
        flash("Invalid username or password.", "error")

    return render_template("admin_login.html", captcha=captcha_html())


@app.route("/logout")
def logout():
    write_audit("logout")
    session.pop("admin", None)
    session.pop("admin_user", None)
    session.pop("admin_role", None)
    return redirect(url_for("admin_login"))


@app.route("/dashboard")
def dashboard():
    guard = admin_required()
    if guard:
        return guard

    total_scans   = History.query.count()
    flagged_count = History.query.filter_by(flagged=True).count()
    total_users   = User.query.count()

    try:
        total_image_scans = AuditLog.query.filter_by(action="image_osint_scan").count()
    except Exception:
        total_image_scans = 0

    week_ago     = datetime.utcnow() - timedelta(days=7)
    recent_count = History.query.filter(History.scanned_at >= week_ago).count()

    labels, scan_counts = [], []
    for i in range(6, -1, -1):
        day       = datetime.utcnow() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end   = day_start + timedelta(days=1)
        count = History.query.filter(
            History.scanned_at >= day_start,
            History.scanned_at < day_end
        ).count()
        labels.append(day.strftime("%b %d"))
        scan_counts.append(count)

    all_targets = [h.target for h in History.query.all()]
    top_targets = Counter(all_targets).most_common(5)
    top_labels  = [t[0] for t in top_targets]
    top_counts  = [t[1] for t in top_targets]
    latest      = History.query.order_by(History.id.desc()).limit(10).all()

    try:
        failed_login_count  = AuditLog.query.filter_by(action="failed_login").count()
        success_login_count = AuditLog.query.filter_by(action="login").count()
    except Exception:
        failed_login_count  = 0
        success_login_count = 0

    return render_template(
        "admin_dashboard.html",
        total_scans=total_scans,
        flagged_count=flagged_count,
        total_users=total_users,
        total_image_scans=total_image_scans,
        recent_count=recent_count,
        latest=latest,
        admin_user=session.get("admin_user", "admin"),
        admin_role=session.get("admin_role", "viewer"),
        chart_labels=labels,
        chart_counts=scan_counts,
        top_labels=top_labels,
        top_counts=top_counts,
        security_events=_security_events,
        failed_login_count=failed_login_count,
        success_login_count=success_login_count,
        rate_limit_rules={
            "scan":      "10 / minute · 100 / day",
            "login":     "5 / minute · 20 / hour",
            "api":       "60 / minute",
            "export":    "10 / hour",
            "sensitive": "3 / minute · 10 / hour",
        },
        jwt_protected_routes=[
            "GET /api/result",
            "GET /api/dashboard-stats  (analyst+)",
            "GET /api/target-history",
        ],
        sqli_patterns_active=True,
        captcha_on_scan=True,
    )


@app.route("/admin/delete/<int:history_id>", methods=["POST"])
def delete_history(history_id):
    guard = admin_required()
    if guard:
        return guard
    block = role_required("analyst")
    if block:
        return block
    entry  = History.query.get_or_404(history_id)
    target = entry.target
    db.session.delete(entry)
    db.session.commit()
    write_audit("deleted_history", f"id={history_id} target={target}")
    flash(f"Deleted scan: {target}", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin/delete-all", methods=["POST"])
def delete_all_history():
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    count = History.query.count()
    History.query.delete()
    db.session.commit()
    write_audit("deleted_all_history", f"count={count}")
    flash(f"Deleted all {count} scan records.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin/export-csv")
@export_limit
def export_csv():
    guard = admin_required()
    if guard:
        return guard
    block = role_required("analyst")
    if block:
        return block
    try:
        rows = History.query.order_by(History.id.desc()).all()
        data = [
            (
                r.id,
                r.target,
                r.scanned_at.strftime("%Y-%m-%d %H:%M:%S") if r.scanned_at else "",
                "Yes" if r.flagged else "No",
                r.scan_type or "full",
            )
            for r in rows
        ]
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Target", "Scanned At", "Flagged", "Scan Type"])
        writer.writerows(data)
        write_audit("exported_csv", f"rows={len(data)}")
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=osint_history.csv"},
        )
    except Exception as e:
        print(f"[CSV Export Error] {e}")
        abort(500)


@app.route("/admin/export-csv/<int:scan_id>")
@export_limit
def export_csv_single(scan_id):
    guard = admin_required()
    if guard:
        return guard
    try:
        r = History.query.get_or_404(scan_id)
        data = (
            r.id,
            r.target,
            r.scanned_at.strftime("%Y-%m-%d %H:%M:%S") if r.scanned_at else "",
            "Yes" if r.flagged else "No",
            r.scan_type or "full",
        )
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Target", "Scanned At", "Flagged", "Scan Type"])
        writer.writerow(data)
        write_audit("exported_csv_single", f"id={scan_id} target={r.target}")
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=osint_{r.target}_{scan_id}.csv"},
        )
    except Exception as e:
        print(f"[CSV Single Error] {e}")
        abort(500)


@app.route("/admin/users")
def manage_users():
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    users = User.query.order_by(User.id).all()
    return render_template("admin_users.html", users=users,
                           admin_user=session.get("admin_user"),
                           admin_role=session.get("admin_role"))


@app.route("/admin/users/add", methods=["POST"])
@sensitive_limit
def add_user():
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "viewer")
    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("manage_users"))
    if role not in ("admin", "analyst", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for("manage_users"))
    if User.query.filter_by(username=username).first():
        flash(f"User '{username}' already exists.", "error")
        return redirect(url_for("manage_users"))
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    write_audit("created_user", f"username={username} role={role}")
    flash(f"User '{username}' created with role '{role}'.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@sensitive_limit
def delete_user(user_id):
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    user = User.query.get_or_404(user_id)
    if user.username == session.get("admin_user"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("manage_users"))
    write_audit("deleted_user", f"username={user.username} role={user.role}")
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/users/role/<int:user_id>", methods=["POST"])
@sensitive_limit
def change_role(user_id):
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "viewer")
    if new_role not in ("admin", "analyst", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for("manage_users"))
    old_role  = user.role
    user.role = new_role
    db.session.commit()
    write_audit("changed_role", f"username={user.username} {old_role}→{new_role}")
    flash(f"'{user.username}' role changed to '{new_role}'.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/audit")
def audit_logs():
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(200).all()
    return render_template("admin_audit.html", logs=logs,
                           admin_user=session.get("admin_user"),
                           admin_role=session.get("admin_role"))


@app.route("/cases")
def cases():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        flash("Case management module not installed.", "error")
        return redirect(url_for("dashboard"))
    status    = request.args.get("status")
    priority  = request.args.get("priority")
    search    = request.args.get("q")
    all_cases = list_cases(status=status, priority=priority, search=search)
    return render_template("cases.html", cases=all_cases,
                           admin_user=session.get("admin_user"),
                           admin_role=session.get("admin_role"),
                           filter_status=status, filter_priority=priority)


@app.route("/cases/create", methods=["POST"])
def create_case_route():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    target   = request.form.get("target", "").strip()
    title    = request.form.get("title", f"Investigation: {target}").strip()
    scan     = _cache_get(target)
    tags_raw = request.form.get("tags", "")
    tags     = [t.strip() for t in tags_raw.split(",") if t.strip()]
    case_id  = create_case(
        title=title, target=target, scan_data=scan,
        description=request.form.get("description", ""),
        priority=request.form.get("priority", "medium"),
        tags=tags,
        created_by=session.get("admin_user", "admin"),
    )
    if case_id:
        write_audit("created_case", f"id={case_id} target={target}")
        flash(f"Case #{case_id} created.", "success")
        return redirect(url_for("view_case", case_id=case_id))
    flash("Failed to create case.", "error")
    return redirect(url_for("cases"))


@app.route("/cases/<int:case_id>")
def view_case(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case  = get_case(case_id)
    notes = get_notes(case_id)
    if not case:
        abort(404)
    return render_template("case_detail.html", case=case, notes=notes,
                           admin_user=session.get("admin_user"),
                           admin_role=session.get("admin_role"))


@app.route("/cases/<int:case_id>/note", methods=["POST"])
def add_case_note(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    content = request.form.get("content", "").strip()
    if content:
        add_note(case_id, content, author=session.get("admin_user", "admin"))
        write_audit("added_note", f"case_id={case_id}")
    return redirect(url_for("view_case", case_id=case_id))


@app.route("/cases/<int:case_id>/update", methods=["POST"])
def update_case_route(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    update_case(case_id,
        status=request.form.get("status"),
        priority=request.form.get("priority"),
        description=request.form.get("description"),
    )
    write_audit("updated_case", f"case_id={case_id}")
    flash("Case updated.", "success")
    return redirect(url_for("view_case", case_id=case_id))


@app.route("/cases/<int:case_id>/export")
def export_case_route(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    fmt = request.args.get("format", "json")
    exp = export_case(case_id)
    if not exp:
        abort(404)
    if fmt == "text":
        return Response(exp.to_text_report(), mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename=case_{case_id}.txt"})
    return Response(exp.to_json(), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=case_{case_id}.json"})


@app.route("/cases/<int:case_id>/delete", methods=["POST"])
def delete_case_route(case_id):
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    if not _HAS_CASES:
        abort(404)
    delete_case(case_id)
    write_audit("deleted_case", f"case_id={case_id}")
    flash("Case deleted.", "success")
    return redirect(url_for("cases"))


@app.route("/cases/<int:case_id>/evidence")
def evidence_center(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case = get_case(case_id)
    if not case:
        abort(404)
    items = list_evidence(case_id)
    summary = evidence_summary(case_id)
    return render_template(
        "evidence_center.html",
        case=case,
        evidence=items,
        summary=summary,
        admin_user=session.get("admin_user"),
        admin_role=session.get("admin_role"),
    )


@app.route("/cases/<int:case_id>/evidence/upload", methods=["POST"])
@sensitive_limit
def evidence_upload(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case = get_case(case_id)
    if not case:
        abort(404)

    category = request.form.get("category", "other")
    file = request.files.get("evidence_file")

    try:
        result = store_file(case_id, file, category=category)
        write_audit("evidence_uploaded", f"case_id={case_id} file={result['filename']}")
        flash(f"Uploaded {result['original_name']} ({result['size_human']}).", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        print(f"[Evidence Upload Error] {e}")
        flash("Failed to upload evidence.", "error")

    return redirect(url_for("evidence_center", case_id=case_id))


@app.route("/cases/<int:case_id>/evidence/note", methods=["POST"])
@sensitive_limit
def evidence_add_note(case_id):
    """Store a free-text investigator note as evidence (Evidence Collection feature)."""
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case = get_case(case_id)
    if not case:
        abort(404)
    content = request.form.get("note_content", "").strip()
    if not content:
        flash("Note content cannot be empty.", "error")
        return redirect(url_for("evidence_center", case_id=case_id))
    try:
        result = store_text(case_id, content, category="note",
                             author=session.get("admin_user", "admin"))
        write_audit("evidence_note_added", f"case_id={case_id}")
        flash("Note added to evidence.", "success")
    except Exception as e:
        print(f"[Evidence Note Error] {e}")
        flash("Failed to save note.", "error")
    return redirect(url_for("evidence_center", case_id=case_id))


@app.route("/cases/<int:case_id>/evidence/snapshot", methods=["POST"])
def evidence_snapshot(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case = get_case(case_id)
    if not case:
        abort(404)

    scan_data = case.get("scan_data") if isinstance(case, dict) else None
    created = snapshot_case(case_id, scan_data=scan_data)
    write_audit("evidence_snapshot", f"case_id={case_id} files={len(created)}")
    flash(f"Snapshot saved: {len(created)} file(s) added to evidence.", "success")
    return redirect(url_for("evidence_center", case_id=case_id))


@app.route("/cases/<int:case_id>/evidence/<string:filename>/download")
def evidence_download(case_id, filename):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    path = get_evidence_path(case_id, filename)
    if not path:
        abort(404)
    folder = os.path.dirname(path)
    return send_from_directory(folder, os.path.basename(path), as_attachment=True)


@app.route("/cases/<int:case_id>/evidence/<string:filename>/delete", methods=["POST"])
def evidence_delete(case_id, filename):
    guard = admin_required()
    if guard:
        return guard
    block = role_required("analyst")
    if block:
        return block
    if not _HAS_CASES:
        abort(404)
    ok = delete_evidence(case_id, filename)
    if ok:
        write_audit("evidence_deleted", f"case_id={case_id} file={filename}")
        flash(f"Deleted evidence: {filename}", "success")
    else:
        flash("Failed to delete evidence file.", "error")
    return redirect(url_for("evidence_center", case_id=case_id))


@app.route("/cases/<int:case_id>/timeline")
def case_timeline(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case = get_case(case_id)
    if not case:
        abort(404)

    events = build_case_timeline(case_id)
    summary = timeline_summary(case_id)

    return render_template(
        "timeline.html",
        case=case,
        events=events,
        summary=summary,
        admin_user=session.get("admin_user"),
        admin_role=session.get("admin_role"),
    )


@app.route("/cases/<int:case_id>/correlation")
def case_correlation(case_id):
    """Cross-Case Correlation view for a single case."""
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES:
        abort(404)
    case = get_case(case_id)
    if not case:
        abort(404)

    correlation = {"error": "Cross-case correlation module not installed."}
    if _HAS_CROSS_CASE:
        try:
            target = case.get("target", "") if isinstance(case, dict) else ""
            scan_data = (case.get("scan_data") if isinstance(case, dict) else None) or {}
            all_cases = list_cases()
            correlation = correlate_cases(target, scan_data, all_cases, exclude_case_id=case_id)
        except Exception as e:
            correlation = {"error": str(e)}

    write_audit("viewed_correlation", f"case_id={case_id}")
    return render_template(
        "case_correlation.html",
        case=case,
        correlation=correlation,
        admin_user=session.get("admin_user"),
        admin_role=session.get("admin_role"),
    )


@app.route("/admin/scheduled")
def scheduled():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_SCHEDULED:
        flash("Scheduled scan module not installed. Run: pip install apscheduler", "error")
        return redirect(url_for("dashboard"))
    targets = sched_list()
    return render_template("scheduled.html", targets=targets,
                           admin_user=session.get("admin_user"),
                           admin_role=session.get("admin_role"))


@app.route("/admin/scheduled/add", methods=["POST"])
def add_scheduled():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_SCHEDULED:
        abort(404)
    target = request.form.get("target", "").strip()
    freq   = request.form.get("frequency", "daily")
    email  = request.form.get("notify_email", "").strip()
    label  = request.form.get("label", "").strip()
    valid, msg = validate_target(target)
    if not valid:
        flash(msg, "error")
        return redirect(url_for("scheduled"))
    sched_add(target, label=label, frequency=freq, notify_email=email)
    write_audit("added_scheduled", f"target={target} freq={freq}")
    flash(f"Monitoring added for {target} ({freq}).", "success")
    return redirect(url_for("scheduled"))


@app.route("/admin/scheduled/delete/<int:tid>", methods=["POST"])
def delete_scheduled(tid):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_SCHEDULED:
        abort(404)
    sched_remove(tid)
    write_audit("removed_scheduled", f"id={tid}")
    flash("Scheduled target removed.", "success")
    return redirect(url_for("scheduled"))


@app.route("/admin/scheduled/toggle/<int:tid>", methods=["POST"])
def toggle_scheduled(tid):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_SCHEDULED:
        abort(404)
    enabled = request.form.get("enabled", "true") == "true"
    sched_toggle(tid, enabled)
    return redirect(url_for("scheduled"))


@app.route("/admin/scheduled/run/<int:tid>", methods=["POST"])
def run_scheduled_now(tid):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_SCHEDULED:
        abort(404)
    sched_run_now(tid, app)
    write_audit("manual_scan", f"scheduled_id={tid}")
    flash("Scan triggered.", "success")
    return redirect(url_for("scheduled"))


@app.route("/admin/alerts")
def alerts_config():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_ALERTS:
        flash("Alert engine module not installed.", "error")
        return redirect(url_for("dashboard"))
    cfg  = get_smtp_config_public()
    logs = get_alert_logs(50)
    return render_template("alerts.html", config=cfg, logs=logs,
                           admin_user=session.get("admin_user"),
                           admin_role=session.get("admin_role"))


@app.route("/admin/alerts/save", methods=["POST"])
def save_alerts_config():
    guard = admin_required()
    if guard:
        return guard
    block = role_required("admin")
    if block:
        return block
    if not _HAS_ALERTS:
        abort(404)
    save_smtp_config(
        host=request.form.get("smtp_host", "smtp.gmail.com"),
        port=int(request.form.get("smtp_port", 587)),
        user=request.form.get("smtp_user", ""),
        password=request.form.get("smtp_password", ""),
        from_email=request.form.get("from_email", ""),
        webhook_url=request.form.get("webhook_url", ""),
    )
    write_audit("saved_alert_config")
    flash("Alert configuration saved.", "success")
    return redirect(url_for("alerts_config"))


@app.route("/admin/alerts/test", methods=["POST"])
@sensitive_limit
def test_alert():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_ALERTS:
        abort(404)
    from modules.alert_engine import send_custom_alert
    to_email = request.form.get("test_email", "").strip()
    if not to_email:
        flash("Enter an email address.", "error")
        return redirect(url_for("alerts_config"))
    result = send_custom_alert(
        "test-target.com", to_email,
        "OSINT Test Alert", "This is a test alert from your OSINT platform.", "info",
    )
    if result.success:
        flash(f"Test alert sent to {to_email} via {result.method}.", "success")
    else:
        flash("Alert failed — check SMTP config.", "error")
    return redirect(url_for("alerts_config"))


@app.route("/admin/reports")
def reports():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_REPORT_DASH:
        flash("Report dashboard module not installed.", "error")
        return redirect(url_for("dashboard"))
    days   = int(request.args.get("days", 30))
    report = build_historical_report(days)
    return render_template("reports.html", report=report, days=days,
                           admin_user=session.get("admin_user"),
                           admin_role=session.get("admin_role"))


@app.route("/admin/reports/export")
@export_limit
def export_report_data():
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_REPORT_DASH:
        abort(404)
    days = int(request.args.get("days", 30))
    data = export_report_json(days)
    write_audit("exported_report", f"days={days}")
    return Response(data, mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=osint_report.json"})


@app.route("/api/dashboard-stats")
@api_limit
@jwt_role_required("analyst")
def api_dashboard_stats():
    _sec_inc("jwt_accepted")
    if not _HAS_REPORT_DASH:
        return jsonify({})
    return jsonify(get_overview_stats())


@app.route("/api/target-history")
@api_limit
@jwt_required
def api_target_history():
    _sec_inc("jwt_accepted")
    target = request.args.get("target", "").strip()
    if not target or not _HAS_REPORT_DASH:
        return jsonify({})
    return jsonify(get_target_history(target))


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message="Bad request."), 400


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Internal server error."), 500


@app.errorhandler(429)
def rate_limited(e):
    _sec_inc("rate_limited")
    return render_template("error.html", code=429, message="Too many requests. Slow down."), 429


@app.route("/cases/<int:case_id>/intelligence")
def case_intelligence(case_id):
    guard = admin_required()
    if guard:
        return guard
    if not _HAS_CASES or not _HAS_INTELLIGENCE:
        flash("Investigation Intelligence module not installed.", "error")
        return redirect(url_for("view_case", case_id=case_id))

    case = get_case(case_id)
    if not case:
        abort(404)

    try:
        notes = get_notes(case_id)
    except Exception as e:
        print(f"[Intelligence] get_notes failed: {e}")
        notes = []

    try:
        intel = analyze_case(case, notes)
        intel_dict = intel.to_dict()
    except Exception as e:
        import traceback
        print(f"[Intelligence] analyze_case failed: {e}")
        traceback.print_exc()
        intel_dict = {
            "confidence": 0, "risk_level": "LOW", "risk_score": 0,
            "signals": {}, "warnings": ["Intelligence analysis failed — see server logs."],
        }

    try:
        all_cases = list_cases()
        similar = find_similar_cases(case, all_cases)
        similar_dicts = [s.to_dict() for s in similar]
    except Exception as e:
        import traceback
        print(f"[Intelligence] find_similar_cases failed: {e}")
        traceback.print_exc()
        similar_dicts = []

    try:
        notes_summary = summarize_notes(notes)
    except Exception as e:
        print(f"[Intelligence] summarize_notes failed: {e}")
        notes_summary = {"total_notes": 0, "authors": [], "latest": None}

    write_audit("viewed_intelligence", f"case_id={case_id}")

    return render_template(
        "case_intelligence.html",
        case=case,
        intel=intel_dict,
        similar_cases=similar_dicts,
        notes_summary=notes_summary,
        admin_user=session.get("admin_user"),
        admin_role=session.get("admin_role"),
    )


# ==========================
# IMAGE OSINT (single, consolidated route — includes full Image
# Intelligence Suite: EXIF metadata, hashing, duplicate detection,
# QR/barcode, OCR, object detection, face detection, landmark
# detection, reverse image search links, GPS extraction, metadata
# risk scoring, AI captioning, AI-generated detection, ELA forgery
# detection, face attributes, image quality, color palette, logo
# detection, vehicle detection, license plate OCR, similarity search)
# Requires login — same public account system as the scanner.
# ==========================

@app.route("/image-osint", methods=["GET", "POST"])
@scan_limit
@login_required
def image_osint():
    if request.method == "POST":
        if "image" not in request.files:
            flash("No image uploaded.", "error")
            return render_template("image_upload.html")

        file = request.files["image"]

        if file.filename == "":
            flash("No file selected.", "error")
            return render_template("image_upload.html")

        if not _allowed_image(file.filename):
            flash(
                f"Invalid file type. Allowed: {', '.join(sorted(ALLOWED_IMAGE_EXTENSIONS))}",
                "error",
            )
            return render_template("image_upload.html")

        file.seek(0, os.SEEK_END)
        size_mb = file.tell() / (1024 * 1024)
        file.seek(0)
        if size_mb > MAX_IMAGE_SIZE_MB:
            flash(f"File too large. Max {MAX_IMAGE_SIZE_MB}MB.", "error")
            return render_template("image_upload.html")

        if not _exiftool_available():
            flash("exiftool is not installed on the server. Run: apt install exiftool", "error")
            return render_template("image_upload.html")

        safe_name = secure_filename(file.filename)
        if not safe_name:
            flash("Invalid filename.", "error")
            return render_template("image_upload.html")

        unique_name = f"{uuid.uuid4().hex}_{safe_name}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_name)

        if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_FOLDER)):
            abort(400, description="Invalid file path.")

        file.save(filepath)

        try:
            # ── EXIF metadata ─────────────────────────────────────────────
            result = subprocess.run(
                ["exiftool", "-j", filepath],
                capture_output=True,
                text=True,
                timeout=15,
            )
            import json
            try:
                parsed = json.loads(result.stdout)
                metadata = parsed[0] if parsed else {}
            except (json.JSONDecodeError, IndexError):
                metadata = {}

            # ── Image Intelligence Suite ─────────────────────────────────
            # Each feature degrades gracefully — a missing dependency or a
            # failed model call never blocks the other features or the
            # original EXIF result.
            image_intel = {}

            # 1. Image Hashing (MD5 / SHA256 / pHash / dHash / aHash / wHash)
            hash_result = None
            if _HAS_IMG_HASH:
                try:
                    hash_result = compute_hashes(filepath)
                    image_intel["hashes"] = hash_result.to_dict()
                except Exception as e:
                    image_intel["hashes"] = {"available": False, "error": str(e)}

            # 2. Duplicate Image Detection (needs the hashes above)
            if _HAS_DUPLICATE and hash_result and hash_result.available:
                try:
                    dup = check_and_index(hash_result.sha256, hash_result.phash, safe_name)
                    image_intel["duplicates"] = dup.to_dict()
                except Exception as e:
                    image_intel["duplicates"] = {"available": False, "error": str(e)}

            # 3. QR / Barcode Detection
            if _HAS_QR:
                try:
                    image_intel["barcodes"] = qr_scan(filepath).to_dict()
                except Exception as e:
                    image_intel["barcodes"] = {"available": False, "error": str(e)}

            # 4. OCR Text Extraction
            if _HAS_OCR:
                try:
                    image_intel["ocr"] = ocr_extract_text(filepath).to_dict()
                except Exception as e:
                    image_intel["ocr"] = {"available": False, "error": str(e)}

            # 5. Object Detection (YOLOv11)
            if _HAS_OBJECT_DETECTION:
                try:
                    image_intel["objects"] = object_detect(filepath).to_dict()
                except Exception as e:
                    image_intel["objects"] = {"available": False, "error": str(e)}

            # 6. Face Detection (detection only — no recognition/identification)
            if _HAS_FACE_DETECTION:
                try:
                    image_intel["faces"] = face_detect(filepath).to_dict()
                except Exception as e:
                    image_intel["faces"] = {"available": False, "error": str(e)}

            # 7. Landmark Detection
            if _HAS_LANDMARK:
                try:
                    image_intel["landmark"] = landmark_detect(filepath).to_dict()
                except Exception as e:
                    image_intel["landmark"] = {"available": False, "error": str(e)}

            # 8. Reverse Image Search
            if _HAS_REVERSE_SEARCH:
                try:
                    image_intel["reverse_search"] = build_reverse_search_links(public_image_url=None).to_dict()
                except Exception as e:
                    image_intel["reverse_search"] = {"available": False, "error": str(e)}

            # 9. GPS Extraction (from EXIF, feeds the map card)
            if _HAS_GPS:
                try:
                    image_intel["gps"] = gps_extract(metadata).to_dict()
                except Exception as e:
                    image_intel["gps"] = {"available": False, "error": str(e)}

            # 10. Metadata Privacy Risk Scoring
            if _HAS_METADATA_RISK:
                try:
                    image_intel["metadata_risk"] = metadata_risk_assess(metadata).to_dict()
                except Exception as e:
                    image_intel["metadata_risk"] = {"available": False, "error": str(e)}

            # 11. AI Image Caption (requires ENABLE_LOCAL_CAPTION_MODEL=true)
            if _HAS_CAPTION:
                try:
                    image_intel["caption"] = ai_caption(filepath).to_dict()
                except Exception as e:
                    image_intel["caption"] = {"available": False, "error": str(e)}

            # 12. AI-Generated Image Detection (requires AI_DETECTOR_API_KEY)
            if _HAS_AI_GENERATED:
                try:
                    image_intel["ai_generated"] = ai_generated_detect(filepath).to_dict()
                except Exception as e:
                    image_intel["ai_generated"] = {"available": False, "error": str(e)}

            # 13. ELA / Forgery Detection
            if _HAS_FORGERY:
                try:
                    image_intel["forgery"] = forgery_analyze(filepath).to_dict()
                except Exception as e:
                    image_intel["forgery"] = {"available": False, "error": str(e)}

            # 14. Face Attributes (age/emotion — requires deepface)
            if _HAS_FACE_ATTRS:
                try:
                    image_intel["face_attributes"] = face_attrs_analyze(filepath).to_dict()
                except Exception as e:
                    image_intel["face_attributes"] = {"available": False, "error": str(e)}

            # 15. Image Quality Analysis (sharpness/brightness/noise)
            if _HAS_QUALITY:
                try:
                    image_intel["quality"] = quality_analyze(filepath).to_dict()
                except Exception as e:
                    image_intel["quality"] = {"available": False, "error": str(e)}

            # 16. Color Palette Extraction
            if _HAS_COLOR_PALETTE:
                try:
                    image_intel["color_palette"] = color_palette_extract(filepath).to_dict()
                except Exception as e:
                    image_intel["color_palette"] = {"available": False, "error": str(e)}

            # 17. Logo & Brand Detection (requires GOOGLE_VISION_API_KEY)
            if _HAS_LOGOS:
                try:
                    image_intel["logos"] = logo_detect(filepath).to_dict()
                except Exception as e:
                    image_intel["logos"] = {"available": False, "error": str(e)}

            # 18. Vehicle Make/Model Detection (requires VEHICLE_MODEL_PATH)
            if _HAS_VEHICLE:
                try:
                    image_intel["vehicle"] = vehicle_detect(filepath).to_dict()
                except Exception as e:
                    image_intel["vehicle"] = {"available": False, "error": str(e)}

            # 19. License Plate OCR
            if _HAS_PLATE:
                try:
                    image_intel["license_plate"] = plate_detect(filepath).to_dict()
                except Exception as e:
                    image_intel["license_plate"] = {"available": False, "error": str(e)}

            # 20. Similarity Search (ranked near-duplicate lookup, needs hashes)
            if _HAS_SIMILARITY and hash_result and hash_result.available:
                try:
                    image_intel["similarity_search"] = similarity_search(
                        hash_result.sha256, hash_result.phash
                    ).to_dict()
                except Exception as e:
                    image_intel["similarity_search"] = {"available": False, "error": str(e)}

            write_audit("image_osint_scan", f"file={safe_name}")
            return render_template(
                "image_result.html",
                metadata=metadata,
                filename=safe_name,
                image_intel=image_intel,
            )

        except subprocess.TimeoutExpired:
            flash("Metadata extraction timed out.", "error")
            return render_template("image_upload.html")

        except Exception as e:
            print(f"[Image OSINT Error] {e}")
            flash("Failed to extract metadata.", "error")
            return render_template("image_upload.html")

        finally:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                pass

    return render_template("image_upload.html")


if __name__ == "__main__":
    # Tables are already created above at import time; this block now only
    # needs to ensure the scheduler is running (in case run_osint_scan
    # wasn't defined yet when _start_scheduler_once() first ran — it always
    # is by this point) and to start Flask's dev server for local runs.
    _start_scheduler_once()

    app.run(
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
    )
