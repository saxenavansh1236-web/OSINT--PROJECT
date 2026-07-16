# security/rate_limiter.py
# Advanced rate limiting for OSINT Platform
# Usage: from security.rate_limiter import limiter, apply_limits

import os
from flask import request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def get_identifier():
    """Use user ID from session if logged in, else fall back to IP."""
    user = session.get("admin_user")
    if user:
        return f"user:{user}"
    return get_remote_address()


# ── Limiter instance ──────────────────────────────────────────────────────────
# Swap storage_uri to Redis in production:
#   storage_uri="redis://localhost:6379"
limiter = Limiter(
    key_func=get_identifier,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    strategy="fixed-window",          # or "moving-window" for stricter enforcement
    headers_enabled=True,             # adds X-RateLimit-* headers to responses
)


def apply_limits(app):
    """Call this in your app factory after limiter.init_app(app)."""
    limiter.init_app(app)

    # Custom JSON error for API consumers
    @app.errorhandler(429)
    def ratelimit_error(e):
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "rate_limit_exceeded",
                "message": str(e.description),
                "retry_after": e.retry_after if hasattr(e, "retry_after") else None,
            }), 429
        return app.jinja_env.get_template("error.html").render(
            code=429, message="Too many requests — slow down."
        ), 429


# ── Per-route limit decorators (import and use in app.py) ────────────────────

# Tight limit on the scan endpoint (most expensive)
scan_limit       = limiter.limit("10 per minute; 100 per day")

# Admin login — brute-force protection
login_limit      = limiter.limit("5 per minute; 20 per hour")

# API endpoints — generous but capped
api_limit        = limiter.limit("60 per minute")

# Export / PDF — heavy operations
export_limit     = limiter.limit("10 per hour")

# Password-reset or alert-test endpoints
sensitive_limit  = limiter.limit("3 per minute; 10 per hour")