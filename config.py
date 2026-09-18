import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _env_float(key, default):
    try:
        return float(os.environ.get(key) or default)
    except (TypeError, ValueError):
        return float(default)


def _env_int(key, default):
    try:
        return int(os.environ.get(key) or default)
    except (TypeError, ValueError):
        return int(default)


def _database_uri():
    uri = os.environ.get("DATABASE_URL")
    if not uri and os.environ.get("VERCEL"):
        # Vercel's filesystem is read-only except /tmp -> throwaway demo DB
        return "sqlite:////tmp/hospital_security.db"
    if not uri:
        uri = f"sqlite:///{os.path.join(BASE_DIR, 'hospital_security.db')}"
    # Render/Heroku-style Postgres URLs use the legacy postgres:// scheme,
    # which SQLAlchemy 2.x rejects -> normalize to postgresql://
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    return uri


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret-key")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)
    JWT_TOKEN_LOCATION = ["headers", "cookies"]
    JWT_COOKIE_SECURE = os.environ.get("JWT_COOKIE_SECURE", "False") == "True"  # True in production (HTTPS)
    JWT_COOKIE_CSRF_PROTECT = False  # simplified for FYP demo scope
    JWT_BLOCKLIST_ENABLED = True
    JWT_BLOCKLIST_TOKEN_CHECKS = ["access"]

    # Risk engine
    RISK_ALERT_THRESHOLD = _env_float("RISK_ALERT_THRESHOLD", 60)
    RISK_AUTO_TERMINATE_THRESHOLD = _env_float("RISK_AUTO_TERMINATE_THRESHOLD", 80)
    MAX_FAILED_LOGIN_ATTEMPTS = _env_int("MAX_FAILED_LOGIN_ATTEMPTS", 4)

    # Behavioral biometrics (UEBA)
    BEHAVIOR_BASELINE_MIN_SESSIONS = _env_int("BEHAVIOR_BASELINE_MIN_SESSIONS", 5)
    BEHAVIOR_DEVIATION_THRESHOLD = _env_float("BEHAVIOR_DEVIATION_THRESHOLD", 2.5)

    ML_MODEL_DIR = os.path.join(BASE_DIR, "ml_models")
