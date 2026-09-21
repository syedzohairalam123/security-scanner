from scanner.correlation import correlate

XSS = {"category": "active_probe", "title": "Potential reflected XSS via 'q' parameter", "severity": "high"}
NO_CSP = {"category": "http_headers", "title": "Missing Content-Security-Policy (CSP) header", "severity": "high"}
WEAK_COOKIE = {"category": "misconfig", "title": "Cookie 'sessionid' missing HttpOnly flag(s)", "severity": "high", "evidence": "sessionid=abc ; missing: HttpOnly"}
EXPOSED_ADMIN = {"category": "access_control", "title": "Admin panel reachable without authentication", "severity": "high"}
GUESSABLE_SESSION = {"category": "token_entropy", "title": "Cookie 'sessionid' looks sequential/predictable", "severity": "high"}
PLAIN_HTTP = {"category": "tls", "title": "Site is served over plain HTTP", "severity": "critical"}
NO_HSTS = {"category": "http_headers", "title": "Missing Strict-Transport-Security (HSTS) header", "severity": "high"}
SQLI = {"category": "active_probe", "title": "Potential SQL injection via 'id' parameter", "severity": "critical"}
VERBOSE_ERRORS = {"category": "misconfig", "title": "Verbose error output detected", "severity": "medium"}
UNRELATED = {"category": "ports", "title": "Port 22 (SSH) is open to the internet", "severity": "low"}


def _titles(chains):
    return [c["title"] for c in chains]


def test_no_chains_when_findings_are_unrelated():
    assert correlate([UNRELATED]) == []


def test_no_chains_from_empty_findings():
    assert correlate([]) == []


def test_xss_chain_requires_both_xss_and_missing_csp():
    assert correlate([XSS]) == []
    assert correlate([NO_CSP]) == []
    chains = correlate([XSS, NO_CSP])
    assert len(chains) == 1
    assert "blast radius" in chains[0]["title"]
    assert chains[0]["severity"] == "high"


def test_xss_chain_escalates_to_critical_with_weak_cookie():
    chains = correlate([XSS, NO_CSP, WEAK_COOKIE])
    assert len(chains) == 1
    assert "session compromise" in chains[0]["title"]
    assert chains[0]["severity"] == "critical"
    # Evidence must name all three constituent findings for auditability.
    assert XSS["title"] in chains[0]["evidence"]
    assert NO_CSP["title"] in chains[0]["evidence"]
    assert WEAK_COOKIE["title"] in chains[0]["evidence"]


def test_admin_takeover_chain():
    assert correlate([EXPOSED_ADMIN]) == []
    chains = correlate([EXPOSED_ADMIN, GUESSABLE_SESSION])
    assert len(chains) == 1
    assert "guessable session" in chains[0]["title"].lower()
    assert chains[0]["severity"] == "critical"


def test_https_downgrade_chain():
    chains = correlate([PLAIN_HTTP, NO_HSTS])
    assert len(chains) == 1
    assert "forced https" in chains[0]["title"].lower()


def test_sqli_plus_verbose_errors_chain():
    chains = correlate([SQLI, VERBOSE_ERRORS])
    assert len(chains) == 1
    assert "verbose error" in chains[0]["title"].lower()
    assert chains[0]["severity"] == "critical"


def test_multiple_independent_chains_can_fire_together():
    chains = correlate([XSS, NO_CSP, WEAK_COOKIE, PLAIN_HTTP, NO_HSTS, SQLI, VERBOSE_ERRORS])
    assert len(chains) == 3


def test_every_chain_has_the_required_fields():
    for chain in correlate([XSS, NO_CSP, WEAK_COOKIE, EXPOSED_ADMIN, GUESSABLE_SESSION, PLAIN_HTTP, NO_HSTS, SQLI, VERBOSE_ERRORS]):
        assert chain["category"] == "attack_chain"
        assert chain["severity"] in ("critical", "high", "medium", "low", "info")
        assert chain["title"]
        assert chain["description"]
        assert chain["evidence"]
        assert chain["recommendation"]
