"""
alert_engine.py
Email alerts and change detection for OSINT monitoring.
Supports SMTP (Gmail / any SMTP), and optional webhook (Slack/Discord).
"""

import os
import json
import smtplib
import hashlib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict

from models import db


# ── SQLAlchemy Model — add to models.py ──────────────────────────────────────
#
# class AlertConfig(db.Model):
#     __tablename__ = "alert_configs"
#     id             = db.Column(db.Integer, primary_key=True)
#     smtp_host      = db.Column(db.String(200), default="smtp.gmail.com")
#     smtp_port      = db.Column(db.Integer, default=587)
#     smtp_user      = db.Column(db.String(200), default="")
#     smtp_password  = db.Column(db.String(500), default="")   # store encrypted in prod
#     from_email     = db.Column(db.String(200), default="")
#     webhook_url    = db.Column(db.String(500), default="")   # Slack/Discord webhook
#     alerts_enabled = db.Column(db.Boolean, default=True)
#     updated_at     = db.Column(db.DateTime, default=datetime.utcnow)
#
# class AlertLog(db.Model):
#     __tablename__ = "alert_logs"
#     id          = db.Column(db.Integer, primary_key=True)
#     target      = db.Column(db.String(500))
#     alert_type  = db.Column(db.String(100))     # change/breach/threat/risk
#     severity    = db.Column(db.String(50))
#     sent_to     = db.Column(db.String(500))
#     message     = db.Column(db.Text)
#     success     = db.Column(db.Boolean, default=True)
#     sent_at     = db.Column(db.DateTime, default=datetime.utcnow)
#
# ─────────────────────────────────────────────────────────────────────────────

try:
    from models import AlertConfig, AlertLog
    _HAS_MODELS = True
except ImportError:
    _HAS_MODELS = False


@dataclass
class AlertResult:
    success: bool
    method: str          # email / webhook / both / none
    message: str
    sent_at: str = ""

    def to_dict(self):
        return asdict(self)


# ── SMTP helpers ──────────────────────────────────────────────────────────────

def _get_smtp_config() -> Dict:
    """Load SMTP config from DB or environment variables."""
    env_config = {
        "host":     os.environ.get("SMTP_HOST", "smtp.gmail.com"),
        "port":     int(os.environ.get("SMTP_PORT", "587")),
        "user":     os.environ.get("SMTP_USER", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from":     os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "")),
    }

    if not _HAS_MODELS:
        return env_config

    try:
        cfg = AlertConfig.query.first()
        if cfg and cfg.smtp_user:
            return {
                "host":     cfg.smtp_host or env_config["host"],
                "port":     cfg.smtp_port or env_config["port"],
                "user":     cfg.smtp_user,
                "password": cfg.smtp_password,
                "from":     cfg.from_email or cfg.smtp_user,
            }
    except Exception:
        pass

    return env_config


def _get_webhook_url() -> str:
    """Get Slack/Discord webhook URL from DB or env."""
    url = os.environ.get("ALERT_WEBHOOK_URL", "")
    if url:
        return url

    if not _HAS_MODELS:
        return ""
    try:
        cfg = AlertConfig.query.first()
        return cfg.webhook_url if cfg else ""
    except Exception:
        return ""


def _log_alert(target: str, alert_type: str, severity: str,
               sent_to: str, message: str, success: bool):
    if not _HAS_MODELS:
        return
    try:
        log = AlertLog(
            target=target, alert_type=alert_type, severity=severity,
            sent_to=sent_to, message=message[:2000], success=success,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[alert_engine/log] {e}")


def _send_email(to_email: str, subject: str, html_body: str, text_body: str = "") -> bool:
    """Send an email via SMTP."""
    cfg = _get_smtp_config()
    if not cfg["user"] or not cfg["password"]:
        print("[alert_engine] SMTP not configured. Set SMTP_USER and SMTP_PASSWORD env vars.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = cfg["from"] or cfg["user"]
        msg["To"]      = to_email

        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
            server.ehlo()
            server.starttls()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["from"] or cfg["user"], to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[alert_engine/smtp] {e}")
        return False


def _send_webhook(payload: Dict) -> bool:
    """Send alert to Slack/Discord webhook."""
    url = _get_webhook_url()
    if not url:
        return False
    try:
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception as e:
        print(f"[alert_engine/webhook] {e}")
        return False


# ── Alert Builders ────────────────────────────────────────────────────────────

def _build_change_email(target: str, result: Dict) -> tuple:
    """Build HTML + text email for change detection alert."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    risk = (result.get("risk_score") or {})
    risk_score = risk.get("total_score", "?")
    risk_level = risk.get("risk_level", "?")
    breach_count = len(result.get("breach") or [])
    dark_flagged = (result.get("dark") or {}).get("flagged", False)
    ip = result.get("ip", "N/A")

    subject = f"[OSINT Alert] Change Detected: {target}"

    html = f"""
    <div style="font-family:monospace;background:#0a0a0f;color:#ccc;padding:24px;border-radius:8px">
        <h2 style="color:#00ff88;letter-spacing:4px">⬡ OSINT ALERT</h2>
        <p style="color:#ff9900;font-size:14px">⚠ Change detected for monitored target</p>
        <hr style="border-color:#1a2a1a">
        <table style="width:100%;font-size:13px">
            <tr><td style="color:#555;width:140px">Target</td><td style="color:#fff">{target}</td></tr>
            <tr><td style="color:#555">IP Address</td><td style="color:#4488ff">{ip}</td></tr>
            <tr><td style="color:#555">Risk Score</td><td style="color:{'#ff3c3c' if isinstance(risk_score, int) and risk_score >= 60 else '#ffaa00'}">{risk_score}/100 ({risk_level})</td></tr>
            <tr><td style="color:#555">Breaches</td><td style="color:{'#ff3c3c' if breach_count else '#00ff88'}">{breach_count} found</td></tr>
            <tr><td style="color:#555">Dark Web</td><td style="color:{'#ff3c3c' if dark_flagged else '#00ff88'}">{'⚠ Flagged' if dark_flagged else '✓ Clean'}</td></tr>
            <tr><td style="color:#555">Detected At</td><td>{ts}</td></tr>
        </table>
        <hr style="border-color:#1a2a1a">
        <p style="font-size:11px;color:#555">OSINT Platform — Automated Monitoring</p>
    </div>
    """
    text = f"OSINT Alert — Change Detected\nTarget: {target}\nIP: {ip}\nRisk: {risk_score}/100\nBreaches: {breach_count}\nDark Web: {'Flagged' if dark_flagged else 'Clean'}\nTime: {ts}"
    return subject, html, text


def _build_breach_email(target: str, breaches: List[Dict]) -> tuple:
    subject = f"[OSINT Alert] New Breach Detected: {target}"
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    breach_rows = ""
    for b in breaches[:10]:
        breach_rows += f"""
        <tr>
            <td style="color:#ff3c3c">{b.get('name','?')}</td>
            <td style="color:#555">{b.get('severity','?').upper()}</td>
            <td style="color:#555">{b.get('date','?')}</td>
            <td style="color:#ff6b35">{'{:,}'.format(b.get('records',0)) if b.get('records') else '?'}</td>
        </tr>"""

    html = f"""
    <div style="font-family:monospace;background:#0a0a0f;color:#ccc;padding:24px;border-radius:8px">
        <h2 style="color:#ff3c3c;letter-spacing:4px">🔓 BREACH ALERT</h2>
        <p>Target <strong style="color:#fff">{target}</strong> found in <strong style="color:#ff3c3c">{len(breaches)}</strong> breach(es)</p>
        <table style="width:100%;font-size:12px;border-collapse:collapse">
            <thead><tr style="color:#555"><th>Breach</th><th>Severity</th><th>Date</th><th>Records</th></tr></thead>
            <tbody>{breach_rows}</tbody>
        </table>
        <p style="font-size:11px;color:#555;margin-top:16px">Detected at {ts} — OSINT Platform</p>
    </div>
    """
    text = f"BREACH ALERT\nTarget: {target}\nBreaches: {len(breaches)}\nTime: {ts}"
    return subject, html, text


def _build_webhook_payload(target: str, alert_type: str, severity: str,
                           summary: str) -> Dict:
    """Build Slack/Discord compatible webhook payload."""
    color_map = {"critical": "#ff0000", "high": "#ff3c3c",
                 "medium": "#ffaa00", "low": "#00ff88", "info": "#4488ff"}
    color = color_map.get(severity, "#555555")

    # Slack format (also works for Discord with embeds)
    return {
        "text": f"*OSINT Alert* — {alert_type}",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Target", "value": target, "short": True},
                    {"title": "Type",   "value": alert_type, "short": True},
                    {"title": "Severity", "value": severity.upper(), "short": True},
                    {"title": "Summary", "value": summary, "short": False},
                ],
                "footer": f"OSINT Platform • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            }
        ],
    }


# ── Public API ────────────────────────────────────────────────────────────────

def send_change_alert(target: str, to_email: str, result: Dict) -> AlertResult:
    """Send a change-detection alert email + webhook."""
    subject, html, text = _build_change_email(target, result)
    email_ok = _send_email(to_email, subject, html, text)

    wh_payload = _build_webhook_payload(
        target, "Change Detected", "medium",
        f"Scan result changed for {target}"
    )
    wh_ok = _send_webhook(wh_payload)

    method = "both" if (email_ok and wh_ok) else ("email" if email_ok else ("webhook" if wh_ok else "none"))
    success = email_ok or wh_ok
    _log_alert(target, "change", "medium", to_email, html[:500], success)

    return AlertResult(
        success=success,
        method=method,
        message=f"Change alert sent to {to_email}" if success else "Alert send failed",
        sent_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def send_breach_alert(target: str, to_email: str, breaches: List[Dict]) -> AlertResult:
    """Send a breach detection alert."""
    subject, html, text = _build_breach_email(target, breaches)
    severity = "critical" if any(b.get("severity") == "critical" for b in breaches) else "high"
    email_ok = _send_email(to_email, subject, html, text)

    wh_payload = _build_webhook_payload(
        target, "Breach Detected", severity,
        f"{len(breaches)} breach(es) found for {target}"
    )
    wh_ok = _send_webhook(wh_payload)

    method = "both" if (email_ok and wh_ok) else ("email" if email_ok else ("webhook" if wh_ok else "none"))
    success = email_ok or wh_ok
    _log_alert(target, "breach", severity, to_email, html[:500], success)

    return AlertResult(
        success=success, method=method,
        message=f"Breach alert sent" if success else "Alert send failed",
        sent_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def send_custom_alert(target: str, to_email: str, subject: str,
                      body: str, severity: str = "info") -> AlertResult:
    """Send a custom alert message."""
    html = f"""
    <div style="font-family:monospace;background:#0a0a0f;color:#ccc;padding:24px;border-radius:8px">
        <h3 style="color:#00ff88">⬡ OSINT Alert: {subject}</h3>
        <p>Target: <strong>{target}</strong></p>
        <pre style="color:#aaa;font-size:12px">{body}</pre>
        <p style="font-size:11px;color:#555">{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
    </div>
    """
    email_ok = _send_email(to_email, f"[OSINT] {subject}", html, body)
    wh_ok    = _send_webhook(_build_webhook_payload(target, subject, severity, body))

    success = email_ok or wh_ok
    method  = "both" if (email_ok and wh_ok) else ("email" if email_ok else ("webhook" if wh_ok else "none"))
    _log_alert(target, "custom", severity, to_email, body[:500], success)

    return AlertResult(
        success=success, method=method,
        message="Alert sent" if success else "Failed",
        sent_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def get_alert_logs(limit: int = 100) -> List[Dict]:
    """Fetch recent alert logs."""
    if not _HAS_MODELS:
        return []
    try:
        logs = AlertLog.query.order_by(AlertLog.id.desc()).limit(limit).all()
        return [
            {
                "id":         l.id,
                "target":     l.target,
                "alert_type": l.alert_type,
                "severity":   l.severity,
                "sent_to":    l.sent_to,
                "success":    l.success,
                "sent_at":    l.sent_at.strftime("%Y-%m-%d %H:%M:%S") if l.sent_at else "",
            }
            for l in logs
        ]
    except Exception as e:
        print(f"[alert_engine/logs] {e}")
        return []


def save_smtp_config(host: str, port: int, user: str, password: str,
                     from_email: str = "", webhook_url: str = "") -> bool:
    """Save SMTP / webhook config to database."""
    if not _HAS_MODELS:
        return False
    try:
        cfg = AlertConfig.query.first()
        if not cfg:
            cfg = AlertConfig()
            db.session.add(cfg)
        cfg.smtp_host    = host
        cfg.smtp_port    = port
        cfg.smtp_user    = user
        cfg.smtp_password = password
        cfg.from_email   = from_email or user
        cfg.webhook_url  = webhook_url
        cfg.updated_at   = datetime.utcnow()
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[alert_engine/save_config] {e}")
        return False


def get_smtp_config_public() -> Dict:
    """Get SMTP config for display (password masked)."""
    cfg = _get_smtp_config()
    return {
        "host":     cfg.get("host", ""),
        "port":     cfg.get("port", 587),
        "user":     cfg.get("user", ""),
        "password": "••••••••" if cfg.get("password") else "",
        "from":     cfg.get("from", ""),
        "configured": bool(cfg.get("user") and cfg.get("password")),
    }