import json

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db
from time_utils import utcnow


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    scans = db.relationship("Scan", backref="user", lazy=True)
    scheduled_targets = db.relationship("ScheduledTarget", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)

    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default="running")  # running | completed | failed
    consent_confirmed = db.Column(db.Boolean, default=False, nullable=False)

    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), default="info")

    started_at = db.Column(db.DateTime, default=utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    # JSON blob of small metadata (resolved IP, detected server, etc.)
    meta_json = db.Column(db.Text, nullable=True)
    # JSON blob comparing this scan to the target's previous scan (new /
    # resolved / recurring findings) - see scan_service.compute_diff().
    diff_summary_json = db.Column(db.Text, nullable=True)

    findings = db.relationship(
        "Finding", backref="scan", lazy=True, cascade="all, delete-orphan",
        order_by="Finding.severity_rank",
    )

    @property
    def meta(self):
        return json.loads(self.meta_json) if self.meta_json else {}

    @meta.setter
    def meta(self, value):
        self.meta_json = json.dumps(value)

    @property
    def diff_summary(self):
        return json.loads(self.diff_summary_json) if self.diff_summary_json else None

    @diff_summary.setter
    def diff_summary(self, value):
        self.diff_summary_json = json.dumps(value) if value is not None else None

    def severity_counts(self):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self, include_findings=True):
        data = {
            "id": self.id,
            "target_url": self.target_url,
            "status": self.status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "meta": self.meta,
            "severity_counts": self.severity_counts(),
        }
        if include_findings:
            data["findings"] = [f.to_dict() for f in self.findings]
        return data


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False, index=True)

    category = db.Column(db.String(50))
    title = db.Column(db.String(255))
    severity = db.Column(db.String(20))  # critical | high | medium | low | info
    severity_rank = db.Column(db.Integer, default=4)

    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    cve_refs = db.Column(db.Text, nullable=True)  # JSON list of {id, cvss, url}
    code_snippet = db.Column(db.Text, nullable=True)
    code_snippet_label = db.Column(db.String(120), nullable=True)
    confidence = db.Column(db.String(10), nullable=True)  # high | medium | low

    def __init__(self, **kwargs):
        kwargs["severity_rank"] = SEVERITY_RANK.get(kwargs.get("severity"), 4)
        super().__init__(**kwargs)

    @property
    def cve_refs_list(self):
        return json.loads(self.cve_refs) if self.cve_refs else []

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cve_refs": self.cve_refs_list,
            "code_snippet": self.code_snippet,
            "code_snippet_label": self.code_snippet_label,
            "confidence": self.confidence,
        }


class ScheduledTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    target_url = db.Column(db.String(500), nullable=False)
    frequency = db.Column(db.String(20), default="daily")  # daily | weekly
    notify_email = db.Column(db.Boolean, default=True)
    active = db.Column(db.Boolean, default=True)

    last_run_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "frequency": self.frequency,
            "notify_email": self.notify_email,
            "active": self.active,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
        }
