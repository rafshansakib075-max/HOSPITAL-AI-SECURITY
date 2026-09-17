import json
from datetime import datetime, timedelta

from flask import Blueprint, render_template, request, redirect, url_for, jsonify
from flask_jwt_extended import get_jwt

from extensions import db
from models import PatientRecord, SecurityAlert, AuditLog, User, SessionActivity, IncidentAction
from audit import log_action, verify_chain
from rbac import any_authenticated_user, role_required, get_current_user
from behavior_biometrics import evaluate_session_deviation
from risk_engine import build_feature_vector, compute_risk_score
from explainability import explain_risk
from incident_response import handle_alert

main_bp = Blueprint("main", __name__)


def _is_off_hours(hour=None):
    hour = hour if hour is not None else datetime.utcnow().hour
    return hour < 6 or hour >= 23


def _mid_session_risk_check(user, rapid_access_count):
    """Runs the AI risk assessment DURING an active session (not just at
    login) using the live behavioral deviation score. This is what makes
    continuous authentication real: a stolen-but-valid token can still be
    caught and the session killed mid-flight if behavior goes anomalous.
    """
    deviation = evaluate_session_deviation(user.id)
    features = build_feature_vector(
        is_new_ip=False,
        is_off_hours=_is_off_hours(),
        recent_failed_attempts=user.failed_login_attempts,
        is_new_device=False,
        rapid_access_count=rapid_access_count,
        behavior_deviation_score=deviation["deviation_score"],
    )
    risk = compute_risk_score(features)

    if risk["should_alert"]:
        claims = get_jwt() or {}
        session_id = claims.get("jti")
        explanation = explain_risk(features)
        alert = SecurityAlert(
            user_id=user.id,
            session_id=session_id,
            alert_type="mid_session_anomaly" if risk["level"] != "critical" else "critical_mid_session_anomaly",
            risk_score=risk["final_score"],
            explanation_json=json.dumps(explanation),
        )
        db.session.add(alert)
        db.session.commit()
        handle_alert(alert, session_id, auto_terminate=risk["should_auto_terminate"])

    return deviation, risk


@main_bp.route("/")
def index():
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@any_authenticated_user
def dashboard():
    user = get_current_user()
    records = PatientRecord.query.limit(10).all()
    log_action(user, "VIEW_DASHBOARD", ip_address=request.remote_addr)

    deviation = evaluate_session_deviation(user.id)
    return render_template("dashboard.html", user=user, records=records, deviation=deviation)


@main_bp.route("/records/<int:record_id>")
@any_authenticated_user
def view_record(record_id):
    user = get_current_user()
    record = PatientRecord.query.get_or_404(record_id)
    log_action(user, "VIEW_PATIENT_RECORD", resource=f"record_id={record_id}", ip_address=request.remote_addr)
    return render_template("patient_records.html", records=[record], user=user, single=True)


@main_bp.route("/records/bulk-export-demo")
@any_authenticated_user
def bulk_export_demo():
    """Demo endpoint that simulates a bulk data pull (e.g. an insider trying
    to exfiltrate many records quickly) so the behavioral biometrics and
    risk engine features can be observed reacting to it in real time.
    """
    user = get_current_user()
    records = PatientRecord.query.all()
    for r in records:
        log_action(user, "VIEW_PATIENT_RECORD", resource=f"record_id={r.id} (bulk_export_demo)",
                   ip_address=request.remote_addr)

    deviation, risk = _mid_session_risk_check(user, rapid_access_count=len(records))

    return render_template(
        "patient_records.html", records=records, user=user, single=False,
        bulk_export_notice=True, deviation=deviation, risk=risk,
        terminated=risk["should_auto_terminate"],
    )


@main_bp.route("/admin/alerts")
@role_required("admin")
def admin_alerts():
    alerts = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).limit(50).all()
    enriched = []
    for a in alerts:
        explanation = json.loads(a.explanation_json) if a.explanation_json else []
        user = User.query.get(a.user_id)
        enriched.append({"alert": a, "explanation": explanation, "username": user.username if user else "?"})
    return render_template("admin_alerts.html", alerts=enriched)


@main_bp.route("/admin/alerts/<int:alert_id>/resolve", methods=["POST"])
@role_required("admin")
def resolve_alert(alert_id):
    admin = get_current_user()
    alert = SecurityAlert.query.get_or_404(alert_id)
    alert.status = request.form.get("status", "resolved")
    alert.resolved_by = admin.username
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    log_action(admin, "ALERT_RESOLVED", resource=f"alert_id={alert_id},status={alert.status}",
               ip_address=request.remote_addr)
    return redirect(url_for("main.admin_alerts"))


@main_bp.route("/admin/users")
@role_required("admin")
def admin_users():
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users)


@main_bp.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
@role_required("admin")
def unlock_user(user_id):
    admin = get_current_user()
    user = User.query.get_or_404(user_id)
    user.is_locked = False
    user.failed_login_attempts = 0
    db.session.commit()
    log_action(admin, "USER_UNLOCKED", resource=f"user_id={user_id}", ip_address=request.remote_addr)
    return redirect(url_for("main.admin_users"))


@main_bp.route("/admin/audit-log")
@role_required("admin")
def audit_log_view():
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(100).all()
    is_valid, broken_id = verify_chain()
    return render_template("audit_log.html", logs=logs, is_valid=is_valid, broken_id=broken_id)


@main_bp.route("/admin/incidents")
@role_required("admin")
def admin_incidents():
    incidents = IncidentAction.query.order_by(IncidentAction.timestamp.desc()).limit(100).all()
    return render_template("admin_incidents.html", incidents=incidents)
