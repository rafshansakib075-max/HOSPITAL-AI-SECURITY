"""
Risk Scoring Engine
====================
Combines simple rule-based heuristics with an unsupervised IsolationForest
anomaly model to produce a single 0-100 risk score for a login/session
event. The feature vector produced here is also what explainability.py
explains with SHAP (Feature #1), and what behavior_biometrics.py's
deviation score feeds into as one of the inputs.
"""
import os
from datetime import datetime

import joblib
import numpy as np
from flask import current_app

FEATURE_NAMES = [
    "is_new_ip",
    "is_off_hours",
    "recent_failed_attempts",
    "is_new_device",
    "rapid_access_count",
    "behavior_deviation_score",
]

_ISOFOREST_PATH_NAME = "isolation_forest.joblib"


def _model_path():
    return os.path.join(current_app.config["ML_MODEL_DIR"], _ISOFOREST_PATH_NAME)


def load_isolation_forest():
    path = _model_path()
    if os.path.exists(path):
        try:
            return joblib.load(path)
        except Exception:
            # Missing sklearn/scipy on minimal installs (e.g. Termux) or
            # version mismatch -> fall back to rule-based scoring only.
            return None
    return None


def build_feature_vector(
    is_new_ip: bool,
    is_off_hours: bool,
    recent_failed_attempts: int,
    is_new_device: bool,
    rapid_access_count: int,
    behavior_deviation_score: float,
):
    return {
        "is_new_ip": int(is_new_ip),
        "is_off_hours": int(is_off_hours),
        "recent_failed_attempts": int(recent_failed_attempts),
        "is_new_device": int(is_new_device),
        "rapid_access_count": int(rapid_access_count),
        "behavior_deviation_score": float(behavior_deviation_score),
    }


def _vector_to_array(features: dict):
    return np.array([[features[name] for name in FEATURE_NAMES]], dtype=float)


# Rule weights: max contribution each feature can add to the 0-100 rule score
RULE_WEIGHTS = {
    "is_new_ip": 15,
    "is_off_hours": 10,
    "recent_failed_attempts": 8,   # per attempt, capped
    "is_new_device": 12,
    "rapid_access_count": 5,       # per extra access over normal, capped
    "behavior_deviation_score": 0.30,  # already 0-100, scaled down as one contributor
}


def rule_based_score(features: dict) -> float:
    score = 0.0
    score += features["is_new_ip"] * RULE_WEIGHTS["is_new_ip"]
    score += features["is_off_hours"] * RULE_WEIGHTS["is_off_hours"]
    score += min(features["recent_failed_attempts"], 5) * RULE_WEIGHTS["recent_failed_attempts"]
    score += features["is_new_device"] * RULE_WEIGHTS["is_new_device"]
    score += min(features["rapid_access_count"], 10) * RULE_WEIGHTS["rapid_access_count"]
    score += features["behavior_deviation_score"] * RULE_WEIGHTS["behavior_deviation_score"]
    return min(score, 100.0)


def anomaly_score(features: dict) -> float:
    """IsolationForest anomaly contribution, scaled to 0-100 (higher = more anomalous)."""
    model = load_isolation_forest()
    if model is None:
        return 0.0
    x = _vector_to_array(features)
    # decision_function: higher = more normal. Flip and rescale to 0-100.
    raw = model.decision_function(x)[0]
    scaled = (0.5 - raw) * 100  # empirically raw is roughly in [-0.3, 0.3]
    return float(np.clip(scaled, 0, 100))


def compute_risk_score(features: dict) -> dict:
    """Combine rule-based and ML anomaly scores into a final 0-100 risk score."""
    rule_score = rule_based_score(features)
    ml_score = anomaly_score(features)
    final_score = round(0.6 * rule_score + 0.4 * ml_score, 1)

    alert_threshold = current_app.config["RISK_ALERT_THRESHOLD"]
    terminate_threshold = current_app.config["RISK_AUTO_TERMINATE_THRESHOLD"]

    if final_score >= terminate_threshold:
        level = "critical"
    elif final_score >= alert_threshold:
        level = "high"
    elif final_score >= alert_threshold * 0.5:
        level = "medium"
    else:
        level = "low"

    return {
        "final_score": final_score,
        "rule_score": round(rule_score, 1),
        "ml_score": round(ml_score, 1),
        "level": level,
        "should_alert": final_score >= alert_threshold,
        "should_auto_terminate": final_score >= terminate_threshold,
        "computed_at": datetime.utcnow().isoformat(),
    }
