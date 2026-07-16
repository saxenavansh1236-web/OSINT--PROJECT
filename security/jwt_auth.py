# security/jwt_auth.py
# JWT authentication for OSINT Platform API endpoints
#
# Setup:
#   pip install PyJWT
#   Set env var: JWT_SECRET_KEY (long random string)
#
# Flow:
#   1. Client POSTs to /api/auth/login  → receives access_token + refresh_token
#   2. Client sends: Authorization: Bearer <access_token> on every API request
#   3. Access token expires in 15 min; client uses refresh token to get a new one
#   4. Refresh token expires in 7 days

import os
import jwt
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Blueprint, request, jsonify, g, current_app
from models import db, User, AuditLog

logger = logging.getLogger("osint.jwt_auth")

JWT_SECRET       = os.environ.get("JWT_SECRET_KEY", os.urandom(32).hex())
JWT_ALGORITHM    = "HS256"
ACCESS_EXPIRES   = timedelta(minutes=15)
REFRESH_EXPIRES  = timedelta(days=7)

# In-memory token blocklist (swap for Redis in production)
_blocklist: set[str] = set()

auth_bp = Blueprint("auth_api", __name__, url_prefix="/api/auth")


# ── Token creation ────────────────────────────────────────────────────────────

def _create_token(user: User, token_type: str, expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":      user.username,
        "role":     user.role,
        "type":     token_type,          # "access" | "refresh"
        "iat":      now,
        "exp":      now + expires,
        "jti":      os.urandom(16).hex(), # unique token ID for blocklisting
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_access_token(user: User) -> str:
    return _create_token(user, "access", ACCESS_EXPIRES)


def create_refresh_token(user: User) -> str:
    return _create_token(user, "refresh", REFRESH_EXPIRES)


# ── Token verification ────────────────────────────────────────────────────────

def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT.
    Raises jwt.PyJWTError subclasses on failure.
    """
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("jti") in _blocklist:
        raise jwt.InvalidTokenError("Token has been revoked.")
    return payload


def _extract_bearer() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


# ── Flask decorator ───────────────────────────────────────────────────────────

def jwt_required(f):
    """
    Protect any route with JWT access-token verification.
    On success, sets g.current_user (username) and g.current_role.

    Example:
        @app.route("/api/scan")
        @jwt_required
        def api_scan():
            print(g.current_user, g.current_role)
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_bearer()
        if not token:
            return jsonify({"error": "Missing Authorization header."}), 401
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired.", "code": "token_expired"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"error": f"Invalid token: {e}"}), 401

        if payload.get("type") != "access":
            return jsonify({"error": "Expected access token."}), 401

        g.current_user = payload["sub"]
        g.current_role = payload.get("role", "viewer")
        g.token_jti    = payload.get("jti")
        return f(*args, **kwargs)
    return decorated


def jwt_role_required(required_role: str):
    """
    Combine JWT check + role enforcement.

    Example:
        @app.route("/api/admin/users")
        @jwt_role_required("admin")
        def api_users(): ...
    """
    roles = {"admin": 3, "analyst": 2, "viewer": 1}

    def decorator(f):
        @wraps(f)
        @jwt_required
        def decorated(*args, **kwargs):
            user_level = roles.get(g.current_role, 0)
            need_level = roles.get(required_role, 99)
            if user_level < need_level:
                return jsonify({
                    "error": "Insufficient permissions.",
                    "required": required_role,
                    "your_role": g.current_role,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Auth routes (register this Blueprint in app.py) ──────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    POST /api/auth/login
    Body: { "username": "...", "password": "..." }
    Returns: { "access_token": "...", "refresh_token": "...", "role": "..." }
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "username and password required."}), 400

    user = User.query.filter_by(username=username, is_active=True).first()
    if not user or not user.check_password(password):
        logger.warning("Failed JWT login for user=%r ip=%s", username, request.remote_addr)
        _write_audit("jwt_login_failed", username, f"ip={request.remote_addr}")
        return jsonify({"error": "Invalid credentials."}), 401

    access_token  = create_access_token(user)
    refresh_token = create_refresh_token(user)

    logger.info("JWT login  user=%r role=%r", username, user.role)
    _write_audit("jwt_login", username, f"role={user.role}")

    return jsonify({
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_type":    "Bearer",
        "expires_in":    int(ACCESS_EXPIRES.total_seconds()),
        "role":          user.role,
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """
    POST /api/auth/refresh
    Body: { "refresh_token": "..." }
    Returns: { "access_token": "..." }
    """
    data  = request.get_json(silent=True) or {}
    token = data.get("refresh_token", "")

    if not token:
        return jsonify({"error": "refresh_token required."}), 400

    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired. Please log in again."}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {e}"}), 401

    if payload.get("type") != "refresh":
        return jsonify({"error": "Expected refresh token."}), 400

    user = User.query.filter_by(username=payload["sub"], is_active=True).first()
    if not user:
        return jsonify({"error": "User not found or deactivated."}), 401

    new_access = create_access_token(user)
    return jsonify({
        "access_token": new_access,
        "token_type":   "Bearer",
        "expires_in":   int(ACCESS_EXPIRES.total_seconds()),
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required
def logout():
    """
    POST /api/auth/logout
    Revokes the current access token (adds its jti to the blocklist).
    """
    _blocklist.add(g.token_jti)
    _write_audit("jwt_logout", g.current_user)
    return jsonify({"message": "Logged out successfully."}), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required
def me():
    """GET /api/auth/me — returns the current user's info."""
    return jsonify({
        "username": g.current_user,
        "role":     g.current_role,
    }), 200


# ── Helper ────────────────────────────────────────────────────────────────────

def _write_audit(action: str, user: str, detail: str = ""):
    try:
        log = AuditLog(
            admin_user=user,
            action=action,
            detail=detail,
            ip_address=request.remote_addr or "",
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error("Audit write failed: %s", e)