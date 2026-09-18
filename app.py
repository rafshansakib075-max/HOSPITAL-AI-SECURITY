from flask import Flask, jsonify
import os
import sys

from config import Config
from extensions import db, jwt, bcrypt, JWT_BLOCKLIST


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        return jwt_payload.get("jti") in JWT_BLOCKLIST

    @jwt.revoked_token_loader
    def revoked_token_response(jwt_header, jwt_payload):
        return jsonify({"error": "Session has been terminated by the security system."}), 401

    @jwt.unauthorized_loader
    def unauthorized_response(reason):
        from flask import redirect, url_for
        return redirect(url_for("auth.login"))

    @jwt.invalid_token_loader
    def invalid_token_response(reason):
        from flask import redirect, url_for
        return redirect(url_for("auth.login"))

    from auth import auth_bp
    from routes_main import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.context_processor
    def inject_current_user():
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
        from models import User
        try:
            verify_jwt_in_request(optional=True)
            uid = get_jwt_identity()
            if uid:
                return {"user": User.query.get(int(uid))}
        except Exception:
            pass
        return {"user": None}

    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            # Gunicorn boots several workers at once; they can race to
            # CREATE the same SQLite tables on a fresh volume. The loser
            # hits "table already exists" - harmless, tables are there.
            print(f"Database creation failed: {e}", file=sys.stderr)
            db.session.rollback()
        # Ephemeral hosts (Vercel serverless) start with an empty database
        # on every cold start -> auto-seed demo data when opted in.
        # Local installs are unaffected (AUTO_SEED is unset).
        if os.environ.get("AUTO_SEED") == "1":
            try:
                from seed_slim import seed_patient_records, seed_roles_and_users
                seed_roles_and_users()
                seed_patient_records()
            except Exception:
                pass

    return app


app = create_app()

@app.errorhandler(500)
def handle_error(e):
    print(f"Unhandled exception: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", debug=debug, port=port)
