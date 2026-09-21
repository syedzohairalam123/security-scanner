from scan_service import persist_scan
from reports.pdf_report import build_pdf
from reports.csv_report import build_csv

SAMPLE_RESULT = {
    "target_url": "https://example.com",
    "risk_score": 62.4,
    "risk_level": "high",
    "meta": {"open_ports": [22, 8080], "detected_framework": "Flask"},
    "errors": [],
    "duration_ms": 4200,
    "findings": [
        {
            "category": "http_headers", "title": "Missing Content-Security-Policy (CSP) header",
            "severity": "high", "description": "No CSP set.", "evidence": "No csp header on /",
            "recommendation": "Add a CSP.", "code_snippet": "Talisman(app)", "code_snippet_label": "Flask fix",
        },
        {
            "category": "cve", "title": "Publicly known vulnerabilities may affect nginx 1.18.0",
            "severity": "critical", "description": "Matched CVEs.", "evidence": "Server: nginx/1.18.0",
            "recommendation": "Upgrade nginx.",
            "cve_refs": [{"id": "CVE-2021-23017", "cvss": 9.8, "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"}],
        },
        {
            "category": "ports", "title": "No unexpected ports found open", "severity": "info",
            "description": "Clean.", "evidence": "", "recommendation": "None.",
        },
    ],
}


def test_pdf_report_generates_nonempty_bytes(app):
    with app.app_context():
        scan = persist_scan(SAMPLE_RESULT, user_id=None)
        pdf_bytes = build_pdf(scan)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF")
        assert len(pdf_bytes) > 500


def test_csv_report_contains_every_finding(app):
    with app.app_context():
        scan = persist_scan(SAMPLE_RESULT, user_id=None)
        csv_text = build_csv(scan)
        assert "Severity" in csv_text.splitlines()[0]
        assert "CVE-2021-23017" in csv_text
        assert csv_text.count("\n") >= len(SAMPLE_RESULT["findings"])


def _signup(client, email="sched@example.com"):
    return client.post("/signup", data={"email": email, "password": "testpass123", "confirm": "testpass123"})


def test_report_export_requires_ownership(client):
    _signup(client, "owner@example.com")
    with client.application.app_context():
        scan = persist_scan(SAMPLE_RESULT, user_id=None)
        # Attach to a *different* user than the one logged into `client`.
        from extensions import db
        from models import User
        other = User(email="someone-else@example.com")
        other.set_password("whatever123")
        db.session.add(other)
        db.session.commit()
        scan.user_id = other.id
        db.session.commit()
        scan_id = scan.id

    resp = client.get(f"/api/scan/{scan_id}/report.pdf")
    assert resp.status_code == 404


def test_schedule_create_list_delete(client):
    _signup(client)

    resp = client.post("/api/schedule", json={"target_url": "https://example.com", "frequency": "daily", "notify_email": True})
    assert resp.status_code == 200
    schedule_id = resp.get_json()["schedule"]["id"]

    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"example.com" in resp.data

    resp = client.delete(f"/api/schedule/{schedule_id}")
    assert resp.status_code == 200


def test_schedule_requires_login(client):
    resp = client.post("/api/schedule", json={"target_url": "https://example.com"})
    assert resp.status_code in (302, 401)


def test_cron_endpoint_runs_without_secret_when_unset(client, monkeypatch):
    from config import Config
    monkeypatch.setattr(Config, "CRON_SECRET", None)
    resp = client.get("/api/cron/scheduled-scans")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "checked" in data


def test_cron_endpoint_rejects_missing_secret_when_configured(client, monkeypatch):
    from config import Config
    monkeypatch.setattr(Config, "CRON_SECRET", "super-secret")
    resp = client.get("/api/cron/scheduled-scans")
    assert resp.status_code == 401
