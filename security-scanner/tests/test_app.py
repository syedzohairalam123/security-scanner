def test_homepage_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"attacker" in resp.data.lower()


def test_static_assets_served(client):
    assert client.get("/style.css").status_code == 200
    assert client.get("/main.js").status_code == 200


def test_missing_scan_is_404(client):
    resp = client.get("/dashboard/999999")
    assert resp.status_code == 404


def test_history_requires_login(client):
    resp = client.get("/history")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_signup_login_logout_flow(client):
    resp = client.post("/signup", data={
        "email": "student@example.com",
        "password": "testpass123",
        "confirm": "testpass123",
    }, follow_redirects=True)
    assert resp.status_code == 200

    # Signing up logs the user in immediately.
    resp = client.get("/history")
    assert resp.status_code == 200

    client.get("/logout")
    resp = client.get("/history")
    assert resp.status_code == 302

    resp = client.post("/login", data={
        "email": "student@example.com",
        "password": "testpass123",
    }, follow_redirects=True)
    assert resp.status_code == 200
    resp = client.get("/history")
    assert resp.status_code == 200


def test_duplicate_signup_is_rejected(client):
    payload = {"email": "dupe@example.com", "password": "testpass123", "confirm": "testpass123"}
    client.post("/signup", data=payload)
    client.get("/logout")
    resp = client.post("/signup", data=payload, follow_redirects=True)
    assert b"already exists" in resp.data


def test_wrong_password_is_rejected(client):
    client.post("/signup", data={"email": "u@example.com", "password": "correct-horse-1", "confirm": "correct-horse-1"})
    client.get("/logout")
    resp = client.post("/login", data={"email": "u@example.com", "password": "wrong-password"}, follow_redirects=True)
    assert b"Incorrect email or password" in resp.data


def test_ai_ask_reports_not_configured_without_api_key(client, monkeypatch):
    import ai_assistant
    monkeypatch.setattr(ai_assistant.Config, "ANTHROPIC_API_KEY", None)

    client.post("/signup", data={"email": "ai@example.com", "password": "testpass123", "confirm": "testpass123"})
    from scan_service import persist_scan
    from app import create_app  # noqa: F401 - ensures app context helpers are importable

    with client.application.app_context():
        scan = persist_scan(
            {"target_url": "https://example.com", "findings": [], "risk_score": 0, "risk_level": "info",
             "meta": {}, "errors": [], "duration_ms": 10},
            user_id=None,
        )
        scan_id = scan.id

    resp = client.post(f"/api/scan/{scan_id}/ask", json={"question": "What should I fix first?"})
    assert resp.status_code == 503
