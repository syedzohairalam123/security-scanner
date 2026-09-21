import threading
import time
import socket
import pytest


@pytest.fixture()
def app(tmp_path):
    import os
    os.environ["SECRET_KEY"] = "test-secret"
    # A real temp file, not sqlite:///:memory: - an in-memory DB is a
    # separate database per connection under SQLAlchemy's default pooling,
    # so tables created by db.create_all() on one connection would be
    # invisible to the next request's connection.
    db_path = tmp_path / "test.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    from app import create_app
    from extensions import db

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    yield flask_app

    with flask_app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def vulnerable_target():
    """Spins up a tiny local HTTP server with a few deliberate, known
    weaknesses (missing headers, a weak cookie, a reflected parameter) so
    scanner tests assert against ground truth instead of the live internet.
    """
    from flask import Flask, request, make_response

    target = Flask("vulnerable_target_" + str(id(object())))

    @target.route("/")
    def home():
        resp = make_response(
            "<html><body>Hello <a href='/search?q=x'>search</a>"
            "<script src='https://code.jquery.com/jquery-1.9.1.min.js'></script>"
            "<script src='https://example-cdn.test/analytics.js'></script>"
            "</body></html>"
        )
        resp.headers["Server"] = "Werkzeug/3.0.1 Python/3.12"
        resp.set_cookie("sessionid", "12345", httponly=False, samesite=None)
        return resp

    @target.route("/search")
    def search():
        q = request.args.get("q", "")
        return f"<html><body>Results for {q}</body></html>"

    port = _free_port()

    server_thread = threading.Thread(
        target=lambda: target.run(host="127.0.0.1", port=port, use_reloader=False, debug=False),
        daemon=True,
    )
    server_thread.start()

    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"
