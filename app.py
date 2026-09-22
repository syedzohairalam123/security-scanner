from pathlib import Path

from flask import Flask, render_template

from config import Config
from extensions import db, login_manager, csrf


def create_app():
    # static_folder="public" + static_url_path="" mirrors how Vercel serves
    # the public/ directory in production, so local `flask run` behaves the
    # same way as the deployed site. See README.md for details.
    app = Flask(__name__, static_folder="public", static_url_path="")
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Log in to view that page."
    login_manager.login_message_category = "error"
    csrf.init_app(app)

    # Import every model before create_all(). This keeps schema creation
    # deterministic even when a route is not imported during startup.
    from models import User, Scan, Finding, ScheduledTarget

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from routes.main import main_bp
    from routes.auth import auth_bp
    from routes.scan import scan_bp
    from routes.cron import cron_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(cron_bp)

    @app.after_request
    def set_security_headers(response):
        # The scanner practices what it checks for.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        return response

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="That page doesn't exist."), 404

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", code=500, message="Something went wrong on our end."), 500

    try:
        Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    except OSError:
        pass  # Vercel's filesystem is read-only outside /tmp
    with app.app_context():
        try:
            db.create_all()
        except Exception:
            pass  # Tables will be created on first successful connection

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
