"""Flask application factory and Vercel entrypoint.

``app = create_app()`` at the bottom of this module is what Vercel imports, so
every line between here and there runs inside the function bootstrap. Vercel
reports a failure there as nothing more than ``could not import 'app.py'``
plus a traceback, which makes the failing *stage* worth logging explicitly -
`_log_startup_stage()` below does that and re-raises, so the real error is
never hidden, just labelled.
"""

import logging
import sys
import traceback
from pathlib import Path

from flask import Flask, render_template

from config import Config, ON_VERCEL
from extensions import db, login_manager, csrf


logger = logging.getLogger("security_scanner")


def _register_logging() -> None:
    """Make our own log records show up in Vercel's runtime logs.

    Without a handler, ``logging`` only emits WARNING and above through its
    last-resort stderr handler, which is enough for startup failures but not
    for the informational startup summary we want here.
    """
    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _log_startup_stage(stage: str, exc: BaseException) -> None:
    """Log which startup stage failed, then let the caller re-raise."""
    logger.error("startup failed during %s: %s: %s", stage, type(exc).__name__, exc)
    logger.error(traceback.format_exc())


def _describe_database(uri: str) -> str:
    """Database URL without credentials, for the startup log."""
    scheme = uri.split("://", 1)[0] or "unknown"
    if scheme.startswith("sqlite"):
        return f"{scheme} (ephemeral, per-instance)" if ON_VERCEL else f"{scheme} (local file)"
    return scheme


def _register_blueprints(app: Flask) -> None:
    # Import every model before create_all(). This keeps schema creation
    # deterministic even when a route is not imported during startup.
    from models import User, Scan, Finding, ScheduledTarget  # noqa: F401

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


def _prepare_database(app: Flask) -> None:
    """Create the schema on boot when possible, and say so clearly when not.

    A database that cannot be reached or written must not stop the app from
    starting (the failure is a deployment/configuration problem, not an import
    problem) - but it is logged with its real exception, because otherwise
    "no such table" errors on every page look like an unrelated bug.
    """
    try:
        Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    except OSError:
        pass  # Vercel's filesystem is read-only outside /tmp

    with app.app_context():
        try:
            db.create_all()
        except Exception as exc:
            logger.error(
                "database initialisation failed (%s: %s). Database: %s. "
                "Check DATABASE_URL - see README.md.",
                type(exc).__name__,
                exc,
                _describe_database(app.config["SQLALCHEMY_DATABASE_URI"]),
            )


def create_app():
    _register_logging()

    # static_folder="public" + static_url_path="" mirrors how Vercel serves
    # the public/ directory in production, so local `flask run` behaves the
    # same way as the deployed site. See README.md for details.
    app = Flask(__name__, static_folder="public", static_url_path="")
    app.config.from_object(Config)

    try:
        db.init_app(app)
        login_manager.init_app(app)
        login_manager.login_view = "auth.login"
        login_manager.login_message = "Log in to view that page."
        login_manager.login_message_category = "error"
        csrf.init_app(app)
    except Exception as exc:
        _log_startup_stage("extension setup", exc)
        raise

    try:
        _register_blueprints(app)
    except Exception as exc:
        _log_startup_stage("blueprint registration", exc)
        raise

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

    _prepare_database(app)

    logger.info(
        "startup complete: python=%s database=%s ai_assistant=%s email=%s cron_secret=%s",
        sys.version.split()[0],
        _describe_database(app.config["SQLALCHEMY_DATABASE_URI"]),
        "on" if Config.ANTHROPIC_API_KEY else "off",
        "on" if (Config.SMTP_HOST and Config.SMTP_USER and Config.SMTP_PASSWORD) else "off",
        "set" if Config.CRON_SECRET else "unset",
    )
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
