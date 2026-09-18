"""
Explainable AI (XAI) Risk Dashboard
=====================================
Unique feature #1.

A raw risk score like "82/100" tells an administrator THAT something looks
suspicious but not WHY. This module trains a small, interpretable
RandomForestClassifier as a surrogate model over the same feature space
used by the risk engine, and uses SHAP (SHapley Additive exPlanations) to
attribute the model's prediction to individual features. The result is a
plain-English, per-alert breakdown such as:

    "Login from a new IP address contributed +32% to this alert"
    "Unusual off-hours access contributed +18% to this alert"

which is what actually lets a hospital security admin trust and act on an
alert instead of treating the AI as a black box.
"""
import os

try:
    import joblib
except ImportError:  # minimal installs: fallback explanation used
    joblib = None
try:
    import numpy as np
except ImportError:  # minimal installs: fallback explanation used
    np = None
try:
    import shap
except ImportError:  # optional on minimal installs (e.g. Termux); fallback used
    shap = None
from flask import current_app

from risk_engine import FEATURE_NAMES, _vector_to_array

_SURROGATE_MODEL_NAME = "shap_surrogate_rf.joblib"

FRIENDLY_NAMES = {
    "is_new_ip": "Login from a new/unrecognized IP address",
    "is_off_hours": "Access during unusual off-hours",
    "recent_failed_attempts": "Recent failed login attempts",
    "is_new_device": "Login from a new/unrecognized device",
    "rapid_access_count": "Unusually rapid record access (possible bulk pull)",
    "behavior_deviation_score": "Deviation from the user's normal behavior pattern",
}


def _surrogate_path():
    return os.path.join(current_app.config["ML_MODEL_DIR"], _SURROGATE_MODEL_NAME)


def load_surrogate_model():
    if joblib is None:
        return None
    path = _surrogate_path()
    if os.path.exists(path):
        try:
            return joblib.load(path)
        except Exception:
            # Missing sklearn on minimal installs -> fallback explanation
            return None
    return None


def explain_risk(features: dict, top_k: int = 4):
    """Return a ranked, human-readable list of what drove this risk score.

    Falls back to a simple rule-weight explanation if the SHAP surrogate
    model has not been trained yet (e.g. fresh install before seeding).
    """
    model = load_surrogate_model()
    x = _vector_to_array(features)

    if model is None or shap is None or np is None:
        return _fallback_explanation(features, top_k)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(x)

    # SHAP's binary-classifier output shape varies by version:
    #   - older versions: a list of two (n_samples, n_features) arrays, one per class
    #   - newer versions (this project): a single (n_samples, n_features, n_classes) array
    # In both cases we want the contribution toward class 1 ("risky").
    arr = np.array(shap_values)
    if isinstance(shap_values, list):
        values = arr[1][0]              # list[class][sample, feature]
    elif arr.ndim == 3:
        values = arr[0, :, 1]           # (sample, feature, class) -> class 1
    else:
        values = arr[0]                 # already (sample, feature)
    values = np.array(values).flatten()

    total_abs = np.sum(np.abs(values)) or 1.0
    contributions = []
    for name, val in zip(FEATURE_NAMES, values):
        pct = float(val) / total_abs * 100
        contributions.append(
            {
                "feature": name,
                "label": FRIENDLY_NAMES.get(name, name),
                "impact_pct": round(pct, 1),
                "direction": "increases risk" if val > 0 else "decreases risk",
                "raw_value": features[name],
            }
        )

    contributions.sort(key=lambda c: abs(c["impact_pct"]), reverse=True)
    return contributions[:top_k]


def _fallback_explanation(features: dict, top_k: int):
    """Used only if the SHAP surrogate model file is missing."""
    from risk_engine import RULE_WEIGHTS

    contributions = []
    for name in FEATURE_NAMES:
        val = features[name]
        weight = RULE_WEIGHTS[name]
        contribution = val * weight
        contributions.append(
            {
                "feature": name,
                "label": FRIENDLY_NAMES.get(name, name),
                "impact_pct": round(contribution, 1),
                "direction": "increases risk" if contribution > 0 else "no effect",
                "raw_value": val,
            }
        )
    contributions.sort(key=lambda c: abs(c["impact_pct"]), reverse=True)
    return contributions[:top_k]
