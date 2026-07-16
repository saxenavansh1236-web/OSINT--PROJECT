# security/captcha.py
# hCaptcha + math-based fallback CAPTCHA for OSINT Platform
#
# Setup:
#   pip install requests
#   Set env vars:
#     HCAPTCHA_SITE_KEY   — from https://dashboard.hcaptcha.com
#     HCAPTCHA_SECRET_KEY — from https://dashboard.hcaptcha.com
#
# Usage in templates:
#   {{ captcha_html()|safe }}          → renders the widget
#   verify_captcha(request)            → call in your POST route

import os
import hmac
import hashlib
import random
import time
import requests
from functools import wraps
from flask import request, session, abort, jsonify

HCAPTCHA_SITE_KEY   = os.environ.get("HCAPTCHA_SITE_KEY", "")
HCAPTCHA_SECRET_KEY = os.environ.get("HCAPTCHA_SECRET_KEY", "")
HCAPTCHA_VERIFY_URL = "https://hcaptcha.com/siteverify"

USE_HCAPTCHA = bool(HCAPTCHA_SITE_KEY and HCAPTCHA_SECRET_KEY)


# ── hCaptcha ──────────────────────────────────────────────────────────────────

def captcha_html() -> str:
    """Returns the HTML snippet to embed in any form."""
    if USE_HCAPTCHA:
        return f"""
        <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
        <div class="h-captcha" data-sitekey="{HCAPTCHA_SITE_KEY}"></div>
        """
    # Fallback: math CAPTCHA
    return _math_captcha_html()


def verify_captcha(req) -> tuple[bool, str]:
    """
    Verify the CAPTCHA from a Flask request.
    Returns (success: bool, error_message: str).
    """
    if USE_HCAPTCHA:
        return _verify_hcaptcha(req)
    return _verify_math_captcha(req)


def _verify_hcaptcha(req) -> tuple[bool, str]:
    token = req.form.get("h-captcha-response", "")
    if not token:
        return False, "Please complete the CAPTCHA."
    try:
        resp = requests.post(HCAPTCHA_VERIFY_URL, data={
            "secret":   HCAPTCHA_SECRET_KEY,
            "response": token,
            "remoteip": req.remote_addr,
        }, timeout=5)
        data = resp.json()
        if data.get("success"):
            return True, ""
        codes = data.get("error-codes", [])
        return False, f"CAPTCHA failed: {', '.join(codes)}"
    except Exception as e:
        return False, f"CAPTCHA verification error: {e}"


# ── Math CAPTCHA fallback (no external dependency) ───────────────────────────

def _math_captcha_html() -> str:
    a, b = random.randint(1, 9), random.randint(1, 9)
    answer = a + b
    # Sign the answer so it cannot be tampered with
    token = _sign(str(answer))
    session["captcha_token"] = token
    return f"""
    <div class="captcha-box">
      <label>Prove you're human: {a} + {b} = ?</label>
      <input type="number" name="captcha_answer" required
             placeholder="Enter answer" autocomplete="off" />
      <input type="hidden" name="captcha_token" value="{token}" />
    </div>
    """


def _verify_math_captcha(req) -> tuple[bool, str]:
    answer = req.form.get("captcha_answer", "").strip()
    token  = req.form.get("captcha_token", "")
    if not answer or not token:
        return False, "Please answer the math question."
    expected_token = _sign(answer)
    if not hmac.compare_digest(expected_token, token):
        return False, "Incorrect CAPTCHA answer."
    # Invalidate after one use
    session.pop("captcha_token", None)
    return True, ""


def _sign(value: str) -> str:
    secret = os.environ.get("SECRET_KEY", "fallback-secret")
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


# ── Flask decorator ───────────────────────────────────────────────────────────

def require_captcha(f):
    """
    Decorator: verify CAPTCHA on POST, abort 400 on failure.
    Use on any route that needs protection.

    Example:
        @app.route("/", methods=["GET","POST"])
        @require_captcha
        def home(): ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            ok, msg = verify_captcha(request)
            if not ok:
                if request.path.startswith("/api/"):
                    return jsonify({"error": msg}), 400
                # For HTML forms, store error in session and let the route handle it
                session["captcha_error"] = msg
                abort(400, description=msg)
        return f(*args, **kwargs)
    return decorated