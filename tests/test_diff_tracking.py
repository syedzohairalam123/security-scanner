from scan_service import compute_diff, persist_scan

FINDING_A = {"category": "http_headers", "title": "Missing Content-Security-Policy (CSP) header", "severity": "high"}
FINDING_B = {"category": "tls", "title": "TLS certificate expires soon (10 days)", "severity": "medium"}
FINDING_C = {"category": "misconfig", "title": "Directory listing appears to be enabled", "severity": "medium"}

BASE_RESULT = {
    "target_url": "https://example.com", "risk_score": 40.0, "risk_level": "medium",
    "meta": {}, "errors": [], "duration_ms": 100,
}


def test_no_previous_scan_means_no_diff():
    assert compute_diff([FINDING_A], previous_scan=None) is None


def test_diff_detects_new_and_recurring(app):
    with app.app_context():
        first = persist_scan({**BASE_RESULT, "findings": [FINDING_A, FINDING_B]}, user_id=None)
        second_result = {**BASE_RESULT, "findings": [FINDING_A, FINDING_C]}

        # Simulate what persist_scan does internally, directly, to check compute_diff in isolation too.
        diff = compute_diff(second_result["findings"], first)
        assert diff["new_count"] == 1
        assert diff["resolved_count"] == 1
        assert diff["recurring_count"] == 1
        assert FINDING_C["title"] in diff["new_titles"]
        assert FINDING_B["title"] in diff["resolved_titles"]
        assert diff["previous_scan_id"] == first.id
        assert diff["previous_risk_score"] == 40.0


def test_persist_scan_auto_attaches_diff_to_the_next_scan_of_same_target(app):
    with app.app_context():
        persist_scan({**BASE_RESULT, "findings": [FINDING_A, FINDING_B], "risk_score": 40.0}, user_id=None)
        second = persist_scan({**BASE_RESULT, "findings": [FINDING_A], "risk_score": 15.0}, user_id=None)

        assert second.diff_summary is not None
        assert second.diff_summary["resolved_count"] == 1
        assert second.diff_summary["new_count"] == 0
        assert second.diff_summary["previous_risk_score"] == 40.0


def test_diff_is_scoped_per_user_not_global(app):
    with app.app_context():
        from extensions import db
        from models import User

        u1 = User(email="a@example.com"); u1.set_password("testpass123")
        u2 = User(email="b@example.com"); u2.set_password("testpass123")
        db.session.add_all([u1, u2])
        db.session.commit()

        persist_scan({**BASE_RESULT, "findings": [FINDING_A]}, user_id=u1.id)
        # Same target URL, different user - should NOT see u1's scan as "previous".
        second = persist_scan({**BASE_RESULT, "findings": [FINDING_B]}, user_id=u2.id)

        assert second.diff_summary is None


def test_first_scan_of_a_target_has_no_diff(app):
    with app.app_context():
        scan = persist_scan({**BASE_RESULT, "findings": [FINDING_A]}, user_id=None)
        assert scan.diff_summary is None


def test_persist_scan_reports_large_response_fingerprint_delta(app):
    first_fingerprint = {
        "title": "Real site",
        "content_length_bucket": "10k-100k",
        "visible_text_hash": "a" * 64,
        "header_names": ["content-type", "strict-transport-security"],
    }
    second_fingerprint = {
        "title": "Verify you are human",
        "content_length_bucket": "under-1k",
        "visible_text_hash": "b" * 64,
        "header_names": ["content-type"],
    }
    with app.app_context():
        persist_scan({**BASE_RESULT, "meta": {"fingerprint": first_fingerprint}, "findings": []})
        second = persist_scan({
            **BASE_RESULT,
            "meta": {"fingerprint": second_fingerprint},
            "findings": [],
        })

        finding = next(f for f in second.findings if f.category == "scan_integrity")
        assert finding.confidence == "medium"
        assert second.meta["fingerprint_delta"]["score"] >= 3
        assert second.diff_summary["fingerprint_delta"]["score"] >= 3
