# Gunicorn config, auto-loaded from the project root.
# Reads $PORT in Python so no shell expansion is needed (Railway's
# Procfile runner does not expand $PORT, which crashed the deploy).
# Works unchanged on Render / Replit / VPS / local.
import os

_candidates = []
_env_port = (os.environ.get("PORT") or "").strip()
if _env_port:
    _candidates.append(_env_port)
# Fallbacks: some hosts do not inject $PORT. Binding the usual suspects
# means the app answers whichever port the platform probes.
for _p in ("8000", "8080", "3000", "5000", "7860", "9000"):
    if _p not in _candidates:
        _candidates.append(_p)

bind = ["0.0.0.0:{}".format(_p) for _p in _candidates]
workers = 2
timeout = 120
