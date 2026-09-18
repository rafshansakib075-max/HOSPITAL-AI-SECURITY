# Gunicorn config, auto-loaded from the project root.
# Reads $PORT in Python so no shell expansion is needed (Railway's
# Procfile runner does not expand $PORT, which crashed the deploy).
# Works unchanged on Render / Replit / VPS / local.
import os

bind = "0.0.0.0:{}".format(os.environ.get("PORT", "8000"))
workers = 2
timeout = 120
