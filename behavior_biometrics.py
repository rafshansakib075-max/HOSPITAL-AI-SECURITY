"""
Behavioral Biometrics / Continuous Authentication (UEBA)
==========================================================
Unique feature #2.

Traditional RBAC + JWT systems only verify identity ONCE, at login. If a
token is stolen or a session is hijacked after a valid login, the system has
no way to notice that the *behavior* on that session no longer matches the
real user.

This module builds a rolling per-user behavioral baseline (actions/minute,
average gap between actions, typical login-hour window) from historical
audit-log activity, then continuously compares the CURRENT session's live
behavior against that baseline using a z-score deviation. A session whose
behavior drifts too far from the user's norm - e.g. a doctor who normally
opens a handful of records per hour suddenly bulk-exporting hundreds of
patient records in two minutes - is flagged in real time, independent of
whether the JWT itself is valid.
"""
from datetime import datetime, timedelta
from statistics import mean, pstdev

from flask import current_app
from extensions import db
from models import AuditLog, BehaviorProfile

MIN_STD = 1e-3  # avoid divide-by-zero on very consistent users


def _historical_events(user_id, lookback_days=30):
    since = datetime.utcnow() - timedelta(days=lookback_days)
    return (
        AuditLog.query.filter(AuditLog.user_id == user_id, AuditLog.timestamp >= since)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )


def compute_live_session_features(user_id, window_minutes=5):
    """Feature vector describing behavior in the last `window_minutes`."""
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    events = (
        AuditLog.query.filter(AuditLog.user_id == user_id, AuditLog.timestamp >= since)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )
    count = len(events)
    actions_per_min = count / max(window_minutes, 1)

    gaps = []
    for a, b in zip(events, events[1:]):
        gaps.append((b.timestamp - a.timestamp).total_seconds())
    avg_gap = mean(gaps) if gaps else None

    return {
        "actions_per_min": actions_per_min,
        "avg_seconds_between_actions": avg_gap,
        "login_hour": datetime.utcnow().hour,
        "event_count": count,
    }


def build_or_refresh_profile(user_id):
    """(Re)build a user's behavioral baseline from historical audit events.
    Called after each session ends, and lazily on first evaluation.
    """
    events = _historical_events(user_id)
    if len(events) < 10:
        return None  # not enough history yet to form a reliable baseline

    # bucket events into 5-minute windows to get an actions/min distribution
    buckets = {}
    for e in events:
        key = e.timestamp.replace(minute=(e.timestamp.minute // 5) * 5, second=0, microsecond=0)
        buckets[key] = buckets.get(key, 0) + 1
    rates = [v / 5.0 for v in buckets.values()]

    gaps = []
    for a, b in zip(events, events[1:]):
        delta = (b.timestamp - a.timestamp).total_seconds()
        if 0 < delta < 600:  # ignore gaps spanning separate sessions
            gaps.append(delta)

    hours = [e.timestamp.hour for e in events]

    profile = BehaviorProfile.query.filter_by(user_id=user_id).first()
    if profile is None:
        profile = BehaviorProfile(user_id=user_id)
        db.session.add(profile)

    profile.avg_actions_per_min = mean(rates) if rates else 0.0
    profile.std_actions_per_min = max(pstdev(rates), MIN_STD) if len(rates) > 1 else 1.0
    profile.avg_seconds_between_actions = mean(gaps) if gaps else 30.0
    profile.std_seconds_between_actions = max(pstdev(gaps), MIN_STD) if len(gaps) > 1 else 15.0
    profile.common_login_hour_start = min(hours) if hours else 8
    profile.common_login_hour_end = max(hours) if hours else 20
    profile.sample_count = len(events)
    profile.updated_at = datetime.utcnow()
    db.session.commit()
    return profile


def evaluate_session_deviation(user_id):
    """Compare live session behavior to the user's baseline.

    Returns a dict with a 0-100 `deviation_score`, a `flag` boolean, and a
    human-readable `reasons` list suitable for display or for feeding into
    the risk engine as an extra feature.
    """
    min_sessions = current_app.config.get("BEHAVIOR_BASELINE_MIN_SESSIONS", 5)
    threshold = current_app.config.get("BEHAVIOR_DEVIATION_THRESHOLD", 2.5)

    profile = BehaviorProfile.query.filter_by(user_id=user_id).first()
    if profile is None or profile.sample_count < min_sessions * 10:
        return {
            "deviation_score": 0.0,
            "flag": False,
            "reasons": ["Baseline still being established - continuous auth not yet active."],
            "baseline_ready": False,
        }

    live = compute_live_session_features(user_id)
    reasons = []
    z_scores = []

    z_rate = (live["actions_per_min"] - profile.avg_actions_per_min) / profile.std_actions_per_min
    z_scores.append(abs(z_rate))
    if z_rate > threshold:
        reasons.append(
            f"Activity rate {live['actions_per_min']:.1f} actions/min is far above "
            f"the usual {profile.avg_actions_per_min:.1f} (possible bulk data pull)."
        )

    if live["avg_seconds_between_actions"] is not None:
        z_gap = (
            profile.avg_seconds_between_actions - live["avg_seconds_between_actions"]
        ) / profile.std_seconds_between_actions
        z_scores.append(abs(z_gap))
        if z_gap > threshold:
            reasons.append("Time between actions is much shorter than usual (bot-like/automated pattern).")

    if not (profile.common_login_hour_start <= live["login_hour"] <= profile.common_login_hour_end):
        z_scores.append(threshold + 0.5)
        reasons.append(
            f"Activity at hour {live['login_hour']}:00 falls outside this user's "
            f"typical {profile.common_login_hour_start}:00-{profile.common_login_hour_end}:00 window."
        )

    deviation_score = min(100.0, (max(z_scores) / (threshold + 1.5)) * 100) if z_scores else 0.0
    flag = max(z_scores) > threshold if z_scores else False

    return {
        "deviation_score": round(deviation_score, 1),
        "flag": flag,
        "reasons": reasons or ["Behavior consistent with established baseline."],
        "baseline_ready": True,
    }
