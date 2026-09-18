# AI-based Insider Threat & Anomaly Detection System for Secure Hospital Data Access

Final Year Design Project. A Flask web application that combines RBAC + JWT
session security with two AI-driven differentiators:

1. **Explainable AI (XAI) Risk Dashboard** - every risk alert shows a
   SHAP-based, plain-English breakdown of exactly which factors drove the
   score (new IP, off-hours access, rapid record access, behavioral
   deviation, etc.), instead of a black-box number.
2. **Behavioral Biometrics / Continuous Authentication (UEBA)** - the system
   builds a rolling per-user behavioral baseline (actions/minute, typical
   login hours, gap between actions) from audit-log history and
   continuously compares *live* session behavior against it, so a
   hijacked-but-valid session can still be caught and killed mid-session -
   not just checked once at login.

## Project Structure

```
hospital_ai_security/
├── app.py                   # Flask application factory + JWT blocklist wiring
├── config.py                 # All configuration / thresholds (via .env)
├── extensions.py              # db, jwt, bcrypt singletons + JWT blocklist set
├── models.py                  # SQLAlchemy models (Role, User, AuditLog, ...)
├── auth.py                    # /login, /logout, /register + risk check at login
├── rbac.py                    # role_required() / any_authenticated_user() decorators
├── audit.py                   # Hash-chained, tamper-evident audit logging
├── risk_engine.py             # Rule-based + IsolationForest risk scoring
├── explainability.py          # FEATURE 1: SHAP-based risk explanation
├── behavior_biometrics.py     # FEATURE 2: UEBA continuous authentication
├── incident_response.py       # Automated session kill / account lock / notify
├── routes_main.py             # Dashboard, patient records, admin views
├── seed_db.py                 # Seeds roles/users/data + trains the ML models
├── requirements.txt
├── .env.example                # Copy to .env and adjust if needed
├── templates/                  # Jinja2 HTML templates
├── static/css/style.css
└── ml_models/                  # isolation_forest.joblib, shap_surrogate_rf.joblib
                                 # (created by seed_db.py)
```

## How the two unique features fit into the architecture

```
Login / mid-session action
        │
        ▼
 behavior_biometrics.py  ──► live deviation score (vs. per-user baseline)
        │
        ▼
 risk_engine.py  ──► rule score + IsolationForest anomaly score ──► final 0-100 risk
        │
        ├── if risk >= alert threshold ──► explainability.py (SHAP) ──► SecurityAlert
        │                                                                    │
        └── if risk >= auto-terminate threshold ──► incident_response.py ◄──┘
                    (kill session / lock account / notify admin)
```

## Setup (local machine)

Requires Python 3.10+.

```bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies (slim set: Flask stack only, rule-based risk mode)
pip install -r requirements.txt

# ...or the full AI stack on a PC/server with plenty of disk:
# pip install -r requirements-ml.txt

# 3. Configure environment
copy .env.example .env


# 4. Seed the database, demo users and patient records
python seed_slim.py

# ...or, with the full ML stack installed, also train the ML models:
# python seed_db.py

# 5. Run the app
python app.py
```

Open **http://127.0.0.1:8002** in your browser.

## Demo login credentials (created by seed_db.py)

| Role   | Username     | Password      |
|--------|--------------|---------------|
| admin  | admin1       | Admin@1234    |
| doctor | dr_rahim     | Doctor@1234   |
| nurse  | nurse_akter  | Nurse@1234    |
| staff  | staff_hasan  | Staff@1234    |

## Demonstrating the features during your defense

1. Log in as `dr_rahim`.
2. On the dashboard, click **"bulk export demo"** - this simulates an
   insider rapidly pulling many patient records at once. Watch the live
   **behavioral deviation score** update in real time.
3. Refresh / click it 2-3 times - you'll see the risk score cross the alert
   threshold, and eventually the account gets **automatically locked** by
   the incident response system (repeated high-risk alerts within 24h).
4. Log in as `admin1` and open **Alerts** - each alert shows the **SHAP
   explanation bars** for exactly which features (rapid access, behavioral
   deviation, etc.) drove the score.
5. Open **Incidents** to see the automated actions the system took
   (session terminated / account locked / admin notified).
6. Open **Audit Log** to see the tamper-evident hash-chained log and its
   integrity verification banner.
7. Open **Users** and unlock the doctor's account to reset the demo.

## Notes on scope (for your report / viva)

- `is_new_device` is a simplified boolean placeholder in this build; a
  production version would fingerprint the device (user agent + TLS/JA3
  hash) rather than hard-coding it.
- The IsolationForest and SHAP surrogate RandomForest are trained on
  **synthetic data** generated in `seed_db.py`, since no real hospital
  incident dataset is publicly available for a system like this - this is
  the same bootstrapping approach used in most insider-threat research
  papers before deployment-time retraining on real logs.
- `JWT_BLOCKLIST` is an in-memory Python set for demo simplicity; swap it
  for Redis in a multi-process/production deployment.
- SQLite is used for zero-setup local grading; swap `DATABASE_URL` in
  `.env` for a PostgreSQL/MySQL URI in production.
