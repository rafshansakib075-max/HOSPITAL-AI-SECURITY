from datetime import datetime
from extensions import db


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # admin, doctor, nurse, staff

    users = db.relationship("User", backref="role", lazy=True)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)

    is_locked = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role.name if self.role else None,
            "is_locked": self.is_locked,
            "failed_login_attempts": self.failed_login_attempts,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class PatientRecord(db.Model):
    __tablename__ = "patient_records"
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(120), nullable=False)
    diagnosis = db.Column(db.String(255), nullable=False)
    sensitive_notes = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    """Hash-chained, tamper-evident audit log.

    Each entry's curr_hash is a SHA-256 digest of the previous entry's hash
    plus this entry's own fields. Any historical edit or deletion breaks the
    chain from that point forward, which verify_chain() can detect.
    """
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username_snapshot = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(120), nullable=False)
    resource = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    prev_hash = db.Column(db.String(64), nullable=False)
    curr_hash = db.Column(db.String(64), nullable=False)


class SessionActivity(db.Model):
    __tablename__ = "session_activity"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_id = db.Column(db.String(64), unique=True, nullable=False)  # JWT jti
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(64), nullable=True)
    device_info = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    actions_count = db.Column(db.Integer, default=0)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    last_risk_score = db.Column(db.Float, default=0.0)
    terminated_reason = db.Column(db.String(255), nullable=True)


class BehaviorProfile(db.Model):
    """Rolling per-user behavioral baseline used for continuous
    authentication (UEBA). Updated incrementally after each session using an
    exponential moving average so the profile adapts slowly over time.
    """
    __tablename__ = "behavior_profiles"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)

    avg_actions_per_min = db.Column(db.Float, default=0.0)
    std_actions_per_min = db.Column(db.Float, default=1.0)
    avg_seconds_between_actions = db.Column(db.Float, default=0.0)
    std_seconds_between_actions = db.Column(db.Float, default=1.0)
    common_login_hour_start = db.Column(db.Integer, default=8)
    common_login_hour_end = db.Column(db.Integer, default=20)

    sample_count = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    session_id = db.Column(db.String(64), nullable=True)
    alert_type = db.Column(db.String(120), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    explanation_json = db.Column(db.Text, nullable=True)  # SHAP-based explanation
    status = db.Column(db.String(30), default="open")  # open, resolved, false_positive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_by = db.Column(db.String(80), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)


class IncidentAction(db.Model):
    __tablename__ = "incident_actions"
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("security_alerts.id"), nullable=False)
    action_type = db.Column(db.String(60), nullable=False)  # session_terminated, account_locked, admin_notified
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(255), nullable=True)
