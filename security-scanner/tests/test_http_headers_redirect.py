from scanner import http_headers


class FakeResponse:
    def __init__(self, url, status_code, headers):
        self.url = url
        self.status_code = status_code
        self.headers = headers


class FakeCtx:
    def __init__(self, redirect_chain, url="https://example.com/"):
        self.redirect_chain = redirect_chain
        self.homepage_response = redirect_chain[-1]
        self.url = url

    @property
    def looks_like_sensitive_page(self):
        return False


def test_hsts_present_on_final_response_needs_no_special_handling():
    final = FakeResponse("https://example.com/", 200, {"Strict-Transport-Security": "max-age=63072000"})
    ctx = FakeCtx([final])
    finding = http_headers._check_hsts_across_redirects(ctx, {"strict-transport-security": "max-age=63072000"})
    assert finding is None


def test_hsts_missing_everywhere_is_reported_as_fully_missing():
    final = FakeResponse("https://example.com/", 200, {})
    ctx = FakeCtx([final])
    finding = http_headers._check_hsts_across_redirects(ctx, {})
    assert finding["title"] == "Missing Strict-Transport-Security (HSTS) header"
    assert finding["severity"] == "high"


def test_hsts_present_only_on_earlier_https_redirect_is_downgraded_not_ignored():
    redirect_hop = FakeResponse("https://example.com/", 301, {"Strict-Transport-Security": "max-age=63072000"})
    final = FakeResponse("https://example.com/home", 200, {})
    ctx = FakeCtx([redirect_hop, final])

    finding = http_headers._check_hsts_across_redirects(ctx, {})
    assert finding is not None
    assert "redirect" in finding["title"].lower()
    assert finding["severity"] == "medium"  # real, but less severe than fully absent
    assert "301" in finding["evidence"]


def test_hsts_on_a_plain_http_redirect_hop_does_not_count():
    # HSTS on an HTTP (not HTTPS) response is meaningless per spec - browsers
    # ignore it there, so it must not suppress the "missing" finding.
    http_hop = FakeResponse("http://example.com/", 301, {"Strict-Transport-Security": "max-age=63072000"})
    final = FakeResponse("https://example.com/", 200, {})
    ctx = FakeCtx([http_hop, final])

    finding = http_headers._check_hsts_across_redirects(ctx, {})
    assert finding["title"] == "Missing Strict-Transport-Security (HSTS) header"


def test_single_hop_no_history_behaves_like_before():
    final = FakeResponse("https://example.com/", 200, {})
    ctx = FakeCtx([final])
    finding = http_headers._check_hsts_across_redirects(ctx, {})
    assert finding["severity"] == "high"
