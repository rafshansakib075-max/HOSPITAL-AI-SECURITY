from datetime import datetime, timedelta

from extensions import db, JWT_BLOCKLIST
from models import SessionActivity, SecurityAlert, IncidentAction, User

REPEAT_ALERT_WINDOW_HOURS = 24
REPEAT_ALERTS_BEFORE_LOCK = 3


def terminate_session(session_id: str, reason: str):
    session = SessionActivity.query.filter_by(session_id=session_id).first()
    if session and session.is_active:
        session.is_active = False
        session.terminated_reason = reason
        JWT_BLOCKLIST.add(session_id)  # revoke the JWT immediately
        db.session.commit()
    return session


def lock_account(user: User, reason: str):
    user.is_locked = True
    db.session.commit()
    return user


def notify_admins(alert: SecurityAlert):
    """Placeholder admin notification. In production this would send an
    email/SMS/Slack message; for the FYP demo it is surfaced on the live
    Admin Alerts dashboard and recorded as an incident action.
    """
    print(f"[ADMIN NOTIFICATION] SecurityAlert #{alert.id} - {alert.alert_type} "
          f"(risk={alert.risk_score}) for user_id={alert.user_id}")


def handle_alert(alert: SecurityAlert, session_id: str, auto_terminate: bool):
    """Orchestrates the automated incident response for a triggered alert."""
    user = User.query.get(alert.user_id)

    if auto_terminate and session_id:
        terminate_session(session_id, reason=f"Auto-terminated: {alert.alert_type} (risk={alert.risk_score})")
        db.session.add(IncidentAction(alert_id=alert.id, action_type="session_terminated",
                                       details=f"risk_score={alert.risk_score}"))

    since = datetime.utcnow() - timedelta(hours=REPEAT_ALERT_WINDOW_HOURS)
    recent_alert_count = SecurityAlert.query.filter(
        SecurityAlert.user_id == user.id, SecurityAlert.created_at >= since
    ).count()

    if recent_alert_count >= REPEAT_ALERTS_BEFORE_LOCK and not user.is_locked:
        lock_account(user, reason="Repeated high-risk alerts within 24 hours")
        db.session.add(IncidentAction(alert_id=alert.id, action_type="account_locked",
                                       details=f"{recent_alert_count} alerts in {REPEAT_ALERT_WINDOW_HOURS}h"))

    notify_admins(alert)
    db.session.add(IncidentAction(alert_id=alert.id, action_type="admin_notified", details="console/dashboard"))
    db.session.commit()
