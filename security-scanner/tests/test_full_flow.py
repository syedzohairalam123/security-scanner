import json


def test_full_flow_scan_stream_then_dashboard(client, vulnerable_target):
    client.post("/signup", data={"email": "flow@example.com", "password": "testpass123", "confirm": "testpass123"})

    resp = client.get(f"/api/scan/stream?target_url={vulnerable_target}&consent=1")
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"

    body = resp.get_data(as_text=True)
    events = [json.loads(line[len("data: "):]) for line in body.splitlines() if line.startswith("data: ")]

    assert events[-1]["type"] == "complete"
    assert "scan_id" in events[-1]
    progress_events = [e for e in events if e["type"] == "progress"]
    assert len(progress_events) >= 8  # one per check module, at minimum

    scan_id = events[-1]["scan_id"]
    dash = client.get(f"/dashboard/{scan_id}")
    assert dash.status_code == 200
    assert vulnerable_target.encode() in dash.data
    assert b"Content-Security-Policy" in dash.data
    assert b"risk-meter-fill" in dash.data


def test_scan_stream_without_consent_is_rejected(client):
    resp = client.get("/api/scan/stream?target_url=example.com&consent=0")
    body = resp.get_data(as_text=True)
    assert "authorized" in body.lower()


def test_scan_stream_without_url_is_rejected(client):
    resp = client.get("/api/scan/stream?consent=1")
    body = resp.get_data(as_text=True)
    assert "enter a target" in body.lower()
