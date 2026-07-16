# security/sql_protection.py
# SQL injection protection for OSINT Platform
#
# Your app already uses SQLAlchemy ORM which parameterises queries automatically.
# This module adds:
#   1. Input sanitisation + pattern detection for scan targets
#   2. A safe raw-query wrapper for any edge cases needing raw SQL
#   3. A request hook that blocks obvious SQLi attempts before they reach routes

import re
import logging
from functools import wraps
from flask import request, abort, jsonify, g
from sqlalchemy import text

logger = logging.getLogger("osint.sql_protection")

# ── Known SQLi patterns ───────────────────────────────────────────────────────
# Covers UNION-based, boolean-blind, time-based, stacked queries, comments, etc.
_SQLI_PATTERNS = [
    r"(\bunion\b.+\bselect\b)",           # UNION SELECT
    r"(\bselect\b.+\bfrom\b)",            # SELECT FROM
    r"(\bdrop\b.+\btable\b)",             # DROP TABLE
    r"(\binsert\b.+\binto\b)",            # INSERT INTO
    r"(\bdelete\b.+\bfrom\b)",            # DELETE FROM
    r"(\bupdate\b.+\bset\b)",             # UPDATE SET
    r"(--|#|/\*)",                         # SQL comments
    r"(\bor\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?)",  # OR 1=1
    r"(\band\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?)", # AND 1=1
    r"(\bsleep\s*\()",                     # time-based blind
    r"(\bbenchmark\s*\()",                 # MySQL benchmark
    r"(\bwaitfor\s+delay\b)",             # MSSQL time-based
    r"(\bexec\s*\()",                      # exec()
    r"(\bxp_cmdshell\b)",                  # MSSQL shell
    r"(\bchar\s*\(\d)",                    # CHAR() encoding
    r"(0x[0-9a-f]{4,})",                  # hex encoding
    r"(\bload_file\s*\()",                 # MySQL file read
    r"(\binto\s+(out|dump)file\b)",       # MySQL file write
]
_SQLI_RE = re.compile(
    "|".join(_SQLI_PATTERNS), re.IGNORECASE | re.DOTALL
)

# Characters that are never valid in a domain / email / phone / username
_FORBIDDEN_CHARS = re.compile(r"[;`$|<>\\]")


# ── Input validator ───────────────────────────────────────────────────────────

class SQLiDetected(ValueError):
    pass


def sanitise_target(target: str) -> str:
    """
    Clean and validate a scan target string.
    Raises SQLiDetected if an injection pattern is found.
    Returns the stripped, safe target string.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string.")

    target = target.strip()

    if len(target) > 253:
        raise ValueError("Target exceeds maximum length (253 chars).")

    if _FORBIDDEN_CHARS.search(target):
        raise ValueError(f"Target contains forbidden characters.")

    if _SQLI_RE.search(target):
        logger.warning(
            "SQLi pattern detected in target=%r  ip=%s",
            target, request.remote_addr if request else "?"
        )
        raise SQLiDetected("Potential SQL injection detected in target.")

    return target


def sanitise_string(value: str, max_len: int = 500, field: str = "input") -> str:
    """Generic string sanitiser for any user-supplied field."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string.")
    value = value.strip()
    if len(value) > max_len:
        raise ValueError(f"{field} is too long (max {max_len} chars).")
    if _SQLI_RE.search(value):
        logger.warning("SQLi pattern in field=%s value=%r", field, value[:80])
        raise SQLiDetected(f"Potential SQL injection in {field}.")
    return value


# ── Safe raw-query wrapper ────────────────────────────────────────────────────

def safe_query(db_session, query_str: str, params: dict = None):
    """
    Execute a raw SQL query safely using SQLAlchemy's parameterised text().
    NEVER use f-strings or string concatenation to build SQL — always use this.

    Example:
        rows = safe_query(db.session,
            "SELECT * FROM history WHERE target = :target LIMIT :lim",
            {"target": "example.com", "lim": 10}
        )
    """
    if params is None:
        params = {}
    # Extra guard: the query template itself must not contain user data
    if _SQLI_RE.search(query_str):
        raise SQLiDetected("Dangerous pattern in raw query template.")
    stmt = text(query_str)
    return db_session.execute(stmt, params)


# ── Flask before_request hook ─────────────────────────────────────────────────

def register_sqli_guard(app):
    """
    Register a before_request hook that inspects all incoming query-string
    and form parameters for obvious injection attempts.
    Attach this in your app factory.

    Usage:
        from security.sql_protection import register_sqli_guard
        register_sqli_guard(app)
    """
    @app.before_request
    def _sqli_guard():
        # Check query string params
        for key, value in request.args.items():
            if _SQLI_RE.search(value):
                logger.warning(
                    "SQLi in query param key=%r value=%r ip=%s path=%s",
                    key, value[:80], request.remote_addr, request.path
                )
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Invalid input detected."}), 400
                abort(400, description="Invalid input detected.")

        # Check form params (skip file uploads)
        if request.method in ("POST", "PUT", "PATCH"):
            for key, value in request.form.items():
                if key in ("password", "smtp_password"):
                    continue   # don't log/inspect passwords
                if isinstance(value, str) and _SQLI_RE.search(value):
                    logger.warning(
                        "SQLi in form param key=%r ip=%s path=%s",
                        key, request.remote_addr, request.path
                    )
                    if request.path.startswith("/api/"):
                        return jsonify({"error": "Invalid input detected."}), 400
                    abort(400, description="Invalid input detected.")


# ── Route decorator ───────────────────────────────────────────────────────────

def sqli_protected(f):
    """
    Decorator: validate the 'target' form/query param for SQL injection
    before the route runs.

    Example:
        @app.route("/", methods=["POST"])
        @sqli_protected
        def home(): ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        target = (
            request.form.get("target") or request.args.get("target", "")
        ).strip()
        if target:
            try:
                g.safe_target = sanitise_target(target)
            except (ValueError, SQLiDetected) as e:
                if request.path.startswith("/api/"):
                    return jsonify({"error": str(e)}), 400
                abort(400, description=str(e))
        return f(*args, **kwargs)
    return decorated