"""Vercel serverless entrypoint (@vercel/python).

Routes all traffic to the Flask app and keeps a throwaway SQLite database
in /tmp (Vercel's filesystem is read-only elsewhere). Demo users/patients
are auto-seeded on cold start when the database is empty.

Limits of this demo adapter (use PythonAnywhere/Render for real hosting):
  - /tmp is per-container and ephemeral: audit logs, alerts and any new
    users vanish when Vercel recycles the container; parallel containers
    do not share data.
  - No ML models here: sklearn/shap are not installed in the serverless
    function, so the app runs in rule-based risk mode (automatic fallback).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Throwaway demo database (writable location on Vercel). A real SECRET_KEY /
# JWT_SECRET_KEY should be set in the Vercel dashboard (Project Settings ->
# Environment Variables); these committed fallbacks are demo-only.
os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/hospital_security.db")
os.environ.setdefault("SECRET_KEY", "vercel-demo-secret-change-me")
os.environ.setdefault("JWT_SECRET_KEY", "vercel-demo-jwt-change-me")
os.environ.setdefault("FLASK_DEBUG", "0")

from app import app  # noqa: E402  (env must be set before import)


class StripApiPrefixMiddleware:
    """Vercel's rewrite forwards the REWRITTEN path (/api/index/...) to the
    function instead of the original URL, so Flask sees /api/index/login
    and 404s. Strip that prefix back off before Flask routes the request.
    Browser-visible URLs are unaffected (redirects still use real paths).
    """

    def __init__(self, wsgi_app, prefix="/api/index"):
        self.wsgi_app = wsgi_app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == self.prefix:
            environ["PATH_INFO"] = "/"
        elif path.startswith(self.prefix + "/"):
            environ["PATH_INFO"] = path[len(self.prefix):]
        return self.wsgi_app(environ, start_response)


app.wsgi_app = StripApiPrefixMiddleware(app.wsgi_app)

with app.app_context():
    from seed_slim import seed_patient_records, seed_roles_and_users

    seed_roles_and_users()
    seed_patient_records()
