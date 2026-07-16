from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ==========================
# USER (with roles)
# ==========================

class User(db.Model):
    __tablename__ = "user"
    __table_args__ = {"extend_existing": True}

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20), default="viewer")  # admin | analyst | viewer
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    is_active     = db.Column(db.Boolean, default=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.username} role={self.role}>"


# ==========================
# HISTORY
# ==========================

class History(db.Model):
    __tablename__ = "history"
    __table_args__ = {"extend_existing": True}

    id         = db.Column(db.Integer, primary_key=True)
    target     = db.Column(db.String(253), nullable=False)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_type  = db.Column(db.String(50), default="full")   # full | whois | subdomain
    flagged    = db.Column(db.Boolean, default=False)        # threat flagged?
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    user       = db.relationship("User", backref="history")

    def __repr__(self):
        return f"<History {self.target} @ {self.scanned_at}>"


# ==========================
# AUDIT LOG
# ==========================

class AuditLog(db.Model):
    __tablename__ = "audit_log"
    __table_args__ = {"extend_existing": True}

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
    admin_user = db.Column(db.String(100), nullable=False)
    action     = db.Column(db.String(100), nullable=False)   # e.g. "deleted_history"
    detail     = db.Column(db.String(500), default="")       # e.g. "target: example.com"
    ip_address = db.Column(db.String(45), default="")

    def __repr__(self):
        return f"<AuditLog {self.admin_user} {self.action} @ {self.timestamp}>"


# ==========================
# CASE MANAGEMENT
# ==========================

class Case(db.Model):
    __tablename__ = "cases"
    __table_args__ = {"extend_existing": True}

    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200), nullable=False)
    target      = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, default="")
    status      = db.Column(db.String(50), default="open")      # open | closed | archived
    priority    = db.Column(db.String(20), default="medium")    # low | medium | high | critical
    tags        = db.Column(db.Text, default="")                # comma-separated
    scan_data   = db.Column(db.Text, default="{}")              # JSON blob of last scan
    created_by  = db.Column(db.String(100), default="admin")
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    case_notes = db.relationship(
        "CaseNote", backref="case", cascade="all, delete-orphan",
        order_by="CaseNote.created_at"
    )

    def __repr__(self):
        return f"<Case #{self.id} {self.title!r} status={self.status}>"


class CaseNote(db.Model):
    __tablename__ = "case_notes"
    __table_args__ = {"extend_existing": True}

    id         = db.Column(db.Integer, primary_key=True)
    case_id    = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    author     = db.Column(db.String(100), default="admin")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<CaseNote case_id={self.case_id} author={self.author}>"


# ==========================
# SCHEDULED SCAN MONITORING
# ==========================
# Backs modules/scheduled_scan.py — required for the "Monitor" page's
# add/remove/toggle/list target functionality (previously left as a
# comment-only TODO, which caused the 500 error on /admin/scheduled/add).

class ScheduledTarget(db.Model):
    __tablename__ = "scheduled_targets"
    __table_args__ = {"extend_existing": True}

    id              = db.Column(db.Integer, primary_key=True)
    target          = db.Column(db.String(500), nullable=False)
    label           = db.Column(db.String(200), default="")
    frequency       = db.Column(db.String(50), default="daily")   # hourly | daily | weekly
    enabled         = db.Column(db.Boolean, default=True)
    last_run        = db.Column(db.DateTime, nullable=True)
    last_hash       = db.Column(db.String(64), default="")        # SHA256 of last result
    change_detected = db.Column(db.Boolean, default=False)
    run_count       = db.Column(db.Integer, default=0)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    notify_email    = db.Column(db.String(200), default="")

    def __repr__(self):
        return f"<ScheduledTarget {self.target} freq={self.frequency} enabled={self.enabled}>"