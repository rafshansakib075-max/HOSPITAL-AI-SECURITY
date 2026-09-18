import json
import uuid
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, make_response, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt, unset_jwt_cookies

from extensions import db, bcrypt
from models import User, Role, SessionActivity, SecurityAlert, AuditLog
from audit import log_action
from rbac import role_required, get_current_user
from behavior_biometrics import evaluate_session_deviation, build_or_refresh_profile
from risk_engine import build_feature_vector, compute_risk_score
from explainability import explain_risk
from incident_response import handle_alert

auth_bp = Blueprint("auth", __name__)


def _recent_failed_attempts(user):
    return user.failed_login_attempts


def _is_new_ip(user, ip):
    return user.last_login_ip is not None and user.last_login_ip != ip


def _is_off_hours(hour=None):
    hour = hour if hour is not None else datetime.utcnow().hour
    return hour < 6 or hour >= 23


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username") or (request.json or {}).get("username")
    password = request.form.get("password") or (request.json or {}).get("password")
    ip_address = request.remote_addr

    user = User.query.filter_by(username=username).first()

    if user is None:
        log_action(None, "LOGIN_FAILED_UNKNOWN_USER", resource=username, ip_address=ip_address)
        return render_template("login.html", error="Invalid credentials"), 401

    if user.is_locked:
        log_action(user, "LOGIN_BLOCKED_ACCOUNT_LOCKED", ip_address=ip_address)
        return render_template("login.html", error="Account is locked. Contact an administrator."), 403

    if not bcrypt.check_password_hash(user.password_hash, password or ""):
        user.failed_login_attempts += 1
        max_attempts = current_app.config["MAX_FAILED_LOGIN_ATTEMPTS"]
        if user.failed_login_attempts >= max_attempts:
            user.is_locked = True
    behavior = {"deviation_score": 0.0}  # TEMP: Skip to diagnose hang
        log_action(user, "LOGIN_FAILED_BAD_PASSWORD", ip_address=ip_address)
        msg = "Invalid credentials"
        if user.is_locked:
            msg = "Account locked after too many failed attempts."
        return render_template("login.html", error=msg), 401

    # --- successful password check: now run the AI risk assessment ---
    behavior = evaluate_session_deviation(user.id)
    risk = {"final_score": 0, "level": "low", "should_alert": False, "should_auto_terminate": False}  # TEMP: Skip
        is_new_ip=_is_new_ip(user, ip_address),
        is_off_hours=_is_off_hours(),
        recent_failed_attempts=_recent_failed_attempts(user),
        is_new_device=False,  # simplified for demo: device fingerprinting not implemented
        rapid_access_count=0,  # not yet known at login time
        behavior_deviation_score=behavior["deviation_score"],
    )
    risk = compute_risk_score(features)

    session_id = str(uuid.uuid4())
    access_token = create_access_token(identity=str(user.id), additional_claims={"jti": session_id})

    session = SessionActivity(
        user_id=user.id,
        session_id=session_id,
        ip_address=ip_address,
        device_info=request.headers.get("User-Agent", "unknown"),
        last_risk_score=risk["final_score"],
    )
    db.session.add(session)

    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    user.last_login_ip = ip_address
    db.session.commit()

    log_action(user, "LOGIN_SUCCESS", resource=f"session={session_id}", ip_address=ip_address)

    if risk["should_alert"]:
        explanation = explain_risk(features)
        alert = SecurityAlert(
            user_id=user.id,
            session_id=session_id,
            alert_type="high_risk_login" if risk["level"] != "critical" else "critical_risk_login",
            risk_score=risk["final_score"],
            explanation_json=json.dumps(explanation),
        )
        db.session.add(alert)
        db.session.commit()
        handle_alert(alert, session_id, auto_terminate=risk["should_auto_terminate"])

        if risk["should_auto_terminate"]:
            return render_template(
                "login.html",
                error="Login blocked by the automated risk engine due to highly anomalous activity. "
                      "An administrator has been notified.",
            ), 403

    resp = make_response(redirect(url_for("main.dashboard")))
    resp.set_cookie("access_token_cookie", access_token, httponly=True, samesite="Lax")
    resp.headers["Authorization"] = f"Bearer {access_token}"
    return resp


@auth_bp.route("/logout")
@jwt_required(optional=True)
def logout():
    claims = get_jwt() or {}
    session_id = claims.get("jti")
    user = get_current_user()

    if session_id:
        session = SessionActivity.query.filter_by(session_id=session_id).first()
        if session:
            session.is_active = False
            session.terminated_reason = "user_logout"
            db.session.commit()
        from extensions import JWT_BLOCKLIST
        JWT_BLOCKLIST.add(session_id)

    if user:
        log_action(user, "LOGOUT", ip_address=request.remote_addr)
        build_or_refresh_profile(user.id)  # refresh behavioral baseline after each session

    resp = make_response(redirect(url_for("auth.login")))
    unset_jwt_cookies(resp)
    return resp


@auth_bp.route("/register", methods=["GET", "POST"])
@role_required("admin")
def register():
    if request.method == "GET":
        roles = Role.query.all()
        return render_template("register.html", roles=roles)

    username = request.form.get("username")
    password = request.form.get("password")
    role_name = request.form.get("role")

    if User.query.filter_by(username=username).first():
        roles = Role.query.all()
        return render_template("register.html", roles=roles, error="Username already exists"), 400

    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        roles = Role.query.all()
        return render_template("register.html", roles=roles, error="Invalid role"), 400

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(username=username, password_hash=password_hash, role_id=role.id)
    db.session.add(user)
    db.session.commit()

    log_action(get_current_user(), "USER_CREATED", resource=f"new_user={username},role={role_name}",
               ip_address=request.remote_addr)

    return redirect(url_for("main.admin_users"))
