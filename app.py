from flask import Flask, jsonify

import os

from config import Config
from extensions import db, jwt, bcrypt, JWT_BLOCKLIST


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # --- JWT blocklist: lets us instantly revoke a session (e.g. when the
    # incident response module auto-terminates a high-risk session) even
    # though the token itself has not expired yet.
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

    # Makes `user` available in EVERY template automatically (base.html's nav
    # bar depends on it). Without this, any route that forgets to pass
    # user=... to render_template() silently loses the top navigation menu -
    # which is exactly the bug this fixes.
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
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8002))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", debug=debug, port=port)
