from scanner import scan_integrity


class FakeResponse:
    def __init__(self, text):
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = {"Content-Type": "text/html", "X-Test": "1"}


class FakeHop:
    def __init__(self, url):
        self.url = url


class FakeCtx:
    def __init__(self, text, redirect_chain=None):
        self.homepage_response = FakeResponse(text)
        self.redirect_chain = redirect_chain or [FakeHop("https://example.com/")]


NORMAL_PAGE = "<html><head><title>Example Site</title></head><body>" + ("Welcome to our real homepage. " * 60) + "</body></html>"


def test_normal_page_produces_no_finding():
    ctx = FakeCtx(NORMAL_PAGE)
    assert scan_integrity.check(ctx) == []


def test_google_bot_detection_marker_is_caught():
    text = "<html><body>Our systems have detected unusual traffic from your computer network. Please try your request again later.</body></html>"
    ctx = FakeCtx(text)
    findings = scan_integrity.check(ctx)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["category"] == "scan_integrity"
    assert "unusual traffic" in findings[0]["evidence"]


def test_cloudflare_challenge_marker_is_caught():
    text = "<html><head><title>Just a moment...</title></head><body>Checking your browser before accessing example.com.</body></html>"
    ctx = FakeCtx(text)
    findings = scan_integrity.check(ctx)
    assert len(findings) == 1
    assert "Just a moment" in findings[0]["evidence"] or "checking your browser" in findings[0]["evidence"].lower()


def test_short_body_after_redirect_is_flagged():
    ctx = FakeCtx("<html><body>Short.</body></html>", redirect_chain=[FakeHop("https://a.com/"), FakeHop("https://b.com/")])
    findings = scan_integrity.check(ctx)
    assert len(findings) == 1
    assert "unusually short" in findings[0]["evidence"]


def test_short_body_without_a_redirect_is_not_flagged():
    # A short but genuine single-page site (no redirect involved) shouldn't
    # be treated as suspicious on length alone.
    ctx = FakeCtx("<html><body>Short.</body></html>", redirect_chain=[FakeHop("https://a.com/")])
    assert scan_integrity.check(ctx) == []


def test_no_response_returns_empty():
    class EmptyCtx:
        homepage_response = None
        redirect_chain = []
    assert scan_integrity.check(EmptyCtx()) == []


def test_page_title_included_in_evidence_when_available():
    text = "<html><head><title>Before you continue to Google Search</title></head><body>Before you continue to Google, we use cookies...</body></html>"
    ctx = FakeCtx(text)
    findings = scan_integrity.check(ctx)
    assert "Before you continue to Google Search" in findings[0]["evidence"]


def test_fingerprint_captures_title_length_text_and_headers():
    fingerprint = scan_integrity.fingerprint_response(FakeResponse(NORMAL_PAGE))
    assert fingerprint["title"] == "Example Site"
    assert fingerprint["content_length_bucket"] == "1k-10k"
    assert len(fingerprint["visible_text_hash"]) == 64
    assert fingerprint["header_names"] == ["content-type", "x-test"]


def test_large_baseline_delta_is_medium_confidence():
    first = scan_integrity.fingerprint_response(FakeResponse(NORMAL_PAGE))
    second = scan_integrity.fingerprint_response(FakeResponse(
        "<html><head><title>Challenge</title></head><body>Verify you are human.</body></html>"
    ))
    delta = scan_integrity.compare_fingerprints(first, second)
    assert delta["score"] >= 3
    finding = scan_integrity.baseline_fingerprint_finding(delta)
    assert finding["confidence"] == "medium"
    assert finding["category"] == "scan_integrity"
