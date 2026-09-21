from config import Config
from scanner import scan_integrity
from scanner import orchestrator
from scanner.orchestrator import run_scan, ScanContext


def _titles(findings):
    return [f["title"] for f in findings]


def test_scan_finds_the_known_weaknesses(vulnerable_target):
    result = run_scan(vulnerable_target, allow_active_probes=True, config=Config)

    assert result["target_url"].startswith("http")
    assert isinstance(result["findings"], list)
    assert result["risk_score"] > 0
    assert result["risk_level"] != "info"

    titles = " | ".join(_titles(result["findings"]))

    # Missing security headers (the target sets none of them).
    assert "Content-Security-Policy" in titles
    assert "Strict-Transport-Security" in titles

    # The weak cookie: no HttpOnly/Secure/SameSite, short numeric value.
    assert any("sessionid" in f["title"] for f in result["findings"])
    assert any(f["category"] == "token_entropy" for f in result["findings"])

    # Server header discloses Werkzeug/Python version.
    assert "Server header" in titles

    # Reflected XSS on /search?q=... (only checked because consent=True).
    assert any(f["category"] == "active_probe" and "XSS" in f["title"] for f in result["findings"])

    # Frontend supply-chain: outdated jQuery + missing-SRI third-party scripts.
    assert any("jQuery" in f["title"] for f in result["findings"])
    assert any(f["category"] == "frontend_supply_chain" and "Subresource Integrity" in f["title"] for f in result["findings"])

    # Correlation engine: this target has exactly the ingredients for two
    # synthesized chains - reflected XSS + no CSP + non-HttpOnly cookie, and
    # plain HTTP + no HSTS.
    chain_titles = [f["title"] for f in result["findings"] if f["category"] == "attack_chain"]
    assert any("session compromise" in t for t in chain_titles)
    assert any("forced HTTPS" in t for t in chain_titles)

    # Confidence tiers made it through on the active-probe findings.
    xss_finding = next(f for f in result["findings"] if f["category"] == "active_probe" and "XSS" in f["title"])
    assert xss_finding["confidence"] in ("high", "medium")


def test_scan_without_consent_skips_active_probes(vulnerable_target):
    result = run_scan(vulnerable_target, allow_active_probes=False, config=Config)
    assert not any(f["category"] == "active_probe" for f in result["findings"])


def test_scan_never_raises_on_unreachable_host():
    # Port 1 on localhost should refuse instantly; the scan should still
    # complete and return a usable (if mostly empty) report rather than
    # raising.
    result = run_scan("http://127.0.0.1:1", allow_active_probes=False, config=Config)
    assert "findings" in result
    assert isinstance(result["risk_score"], float)


def test_scan_rejects_empty_target():
    import pytest
    with pytest.raises(ValueError):
        run_scan("", allow_active_probes=False, config=Config)


def test_scan_context_sends_realistic_navigation_headers():
    ctx = ScanContext("https://example.com", allow_active_probes=False, config=Config)
    assert ctx.session.headers["Accept"].startswith("text/html")
    assert ctx.session.headers["Accept-Language"] == "en-US,en;q=0.9"
    assert ctx.session.headers["Accept-Encoding"] == "gzip, deflate"


def test_interstitial_retry_uses_clean_response_and_sleeps_once(monkeypatch):
    class Response:
        def __init__(self, text):
            self.text = text
            self.content = text.encode("utf-8")
            self.headers = {"Content-Type": "text/html"}
            self.url = "https://example.com/"
            self.history = []
            self.status_code = 200

    challenge = Response("<html><body>Checking your browser before accessing example.com.</body></html>")
    normal = Response("<html><head><title>Example</title></head><body>" + ("Real page. " * 120) + "</body></html>")
    responses = iter([challenge, normal])

    def fake_fetch(self):
        self.homepage_response = next(responses)
        self.redirect_chain = [self.homepage_response]
        self.meta["fingerprint"] = scan_integrity.fingerprint_response(self.homepage_response)

    sleeps = []
    monkeypatch.setattr(orchestrator.ScanContext, "fetch_homepage", fake_fetch)
    monkeypatch.setattr(orchestrator.time, "sleep", sleeps.append)
    monkeypatch.setattr(orchestrator, "CHECK_MODULES", [scan_integrity])

    result = orchestrator.run_scan("https://example.com", False, Config)

    assert sleeps == [2]
    assert len(result["findings"]) == 1
    assert "retried response" in result["findings"][0]["evidence"]


def test_interstitial_retry_stops_after_one_failed_retry(monkeypatch):
    class Response:
        def __init__(self):
            self.text = "<html><body>Verify you are human.</body></html>"
            self.content = self.text.encode("utf-8")
            self.headers = {"Content-Type": "text/html"}
            self.url = "https://example.com/"
            self.history = []
            self.status_code = 200

    response = Response()

    def fake_fetch(self):
        self.homepage_response = response
        self.redirect_chain = [response]
        self.meta["fingerprint"] = scan_integrity.fingerprint_response(response)

    sleeps = []
    monkeypatch.setattr(orchestrator.ScanContext, "fetch_homepage", fake_fetch)
    monkeypatch.setattr(orchestrator.time, "sleep", sleeps.append)
    monkeypatch.setattr(orchestrator, "CHECK_MODULES", [scan_integrity])

    result = orchestrator.run_scan("https://example.com", False, Config)

    assert sleeps == [2]
    assert len(result["findings"]) == 1
    assert "same type of response" in result["findings"][0]["evidence"]
