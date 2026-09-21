import json

from scan_service import persist_scan
from reports.sarif_report import build_sarif

SAMPLE = {
    "target_url": "https://example.com",
    "risk_score": 55.0,
    "risk_level": "high",
    "meta": {},
    "errors": [],
    "duration_ms": 500,
    "findings": [
        {"category": "http_headers", "title": "Missing Content-Security-Policy (CSP) header",
         "severity": "high", "description": "No CSP.", "evidence": "no csp", "recommendation": "Add one.", "confidence": None},
        {"category": "active_probe", "title": "Potential SQL injection via 'id' parameter",
         "severity": "critical", "description": "DB error.", "evidence": "sqlstate[", "recommendation": "Parameterize.", "confidence": "high"},
        {"category": "ports", "title": "No unexpected ports found open",
         "severity": "info", "description": "Clean.", "evidence": "", "recommendation": "None."},
    ],
}


def test_sarif_is_valid_json_with_required_top_level_keys(app):
    with app.app_context():
        scan = persist_scan(SAMPLE, user_id=None)
        sarif_text = build_sarif(scan)
        data = json.loads(sarif_text)  # raises if not valid JSON

        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "Perimeter"


def test_sarif_result_count_matches_finding_count(app):
    with app.app_context():
        scan = persist_scan(SAMPLE, user_id=None)
        data = json.loads(build_sarif(scan))
        assert len(data["runs"][0]["results"]) == len(SAMPLE["findings"])


def test_sarif_severity_maps_to_correct_level(app):
    with app.app_context():
        scan = persist_scan(SAMPLE, user_id=None)
        data = json.loads(build_sarif(scan))
        results = data["runs"][0]["results"]

        critical_result = next(r for r in results if "SQL injection" in r["message"]["text"])
        assert critical_result["level"] == "error"

        info_result = next(r for r in results if "No unexpected ports" in r["message"]["text"])
        assert info_result["level"] == "note"


def test_sarif_rules_are_deduplicated(app):
    with app.app_context():
        two_of_the_same = {**SAMPLE, "findings": [SAMPLE["findings"][0], SAMPLE["findings"][0]]}
        scan = persist_scan(two_of_the_same, user_id=None)
        data = json.loads(build_sarif(scan))
        assert len(data["runs"][0]["results"]) == 2
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1


def test_sarif_carries_confidence_as_a_property(app):
    with app.app_context():
        scan = persist_scan(SAMPLE, user_id=None)
        data = json.loads(build_sarif(scan))
        sqli_result = next(r for r in data["runs"][0]["results"] if "SQL injection" in r["message"]["text"])
        assert sqli_result["properties"]["confidence"] == "high"
