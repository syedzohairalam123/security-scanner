from scanner import dns_security


class FakeTxtRecord:
    """Mimics how dnspython renders a TXT rdata: the character-string
    wrapped in literal double quotes."""
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return f'"{self._text}"'


class FakeCname:
    def __init__(self, target):
        self.target = target + "."  # dnspython targets are absolute (trailing dot)


class FakeCtx:
    def __init__(self, hostname):
        self.hostname = hostname
        self.meta = {}


def test_txt_text_strips_dnspython_quoting():
    assert dns_security._txt_text(FakeTxtRecord("v=spf1 -all")) == "v=spf1 -all"


def test_check_spf_finds_matching_record(monkeypatch):
    def fake_resolve(name, rdtype):
        if rdtype == "TXT":
            return [FakeTxtRecord("some-other-verification=xyz"), FakeTxtRecord("v=spf1 include:_spf.google.com ~all")]
        return []

    monkeypatch.setattr(dns_security, "_resolve", fake_resolve)
    result = dns_security._check_spf("example.com")
    assert result is not None
    assert result.startswith("v=spf1")


def test_check_spf_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr(dns_security, "_resolve", lambda name, rdtype: [])
    assert dns_security._check_spf("example.com") is None


def test_missing_spf_produces_medium_finding(monkeypatch):
    monkeypatch.setattr(dns_security, "_resolve", lambda name, rdtype: [])
    monkeypatch.setattr(dns_security, "_check_takeover", lambda hostname: [])

    findings = dns_security.check(FakeCtx("example.com"))
    spf_findings = [f for f in findings if "SPF" in f["title"]]
    assert len(spf_findings) == 1
    assert spf_findings[0]["severity"] == "medium"
    assert "No SPF" in spf_findings[0]["title"]


def test_permissive_spf_plus_all_is_flagged_high(monkeypatch):
    def fake_resolve(name, rdtype):
        if rdtype == "TXT" and "_dmarc" not in name:
            return [FakeTxtRecord("v=spf1 +all")]
        return []

    monkeypatch.setattr(dns_security, "_resolve", fake_resolve)
    monkeypatch.setattr(dns_security, "_check_takeover", lambda hostname: [])

    findings = dns_security.check(FakeCtx("example.com"))
    plus_all = next(f for f in findings if "+all" in f["title"])
    assert plus_all["severity"] == "high"


def test_dmarc_p_none_is_flagged_low(monkeypatch):
    def fake_resolve(name, rdtype):
        if rdtype == "TXT" and "_dmarc" in name:
            return [FakeTxtRecord("v=DMARC1; p=none; rua=mailto:x@example.com")]
        if rdtype == "TXT":
            return [FakeTxtRecord("v=spf1 -all")]  # keep SPF clean so only DMARC fires
        return []

    monkeypatch.setattr(dns_security, "_resolve", fake_resolve)
    monkeypatch.setattr(dns_security, "_check_takeover", lambda hostname: [])

    findings = dns_security.check(FakeCtx("example.com"))
    dmarc_findings = [f for f in findings if "DMARC" in f["title"]]
    assert len(dmarc_findings) == 1
    assert dmarc_findings[0]["severity"] == "low"
    assert "none" in dmarc_findings[0]["title"].lower()


def test_takeover_fingerprint_matches_confirmed_via_http(monkeypatch):
    monkeypatch.setattr(dns_security, "_resolve", lambda name, rdtype: (
        [FakeCname("forgotten-app.herokuapp.com")] if rdtype == "CNAME" else []
    ))

    class FakeResponse:
        text = "Heroku | No such app"

    monkeypatch.setattr(dns_security.requests, "get", lambda *a, **k: FakeResponse())

    findings = dns_security._check_takeover("old.example.com")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "takeover" in findings[0]["title"].lower()


def test_no_cname_means_no_takeover_check(monkeypatch):
    monkeypatch.setattr(dns_security, "_resolve", lambda name, rdtype: [])
    assert dns_security._check_takeover("example.com") == []


def test_full_check_never_raises_against_a_real_domain():
    # Live smoke test: real DNS queries against a stable domain, asserting
    # only that the function completes and returns a well-formed list -
    # not asserting specific findings, since a third party's DNS config can
    # legitimately change over time.
    findings = dns_security.check(FakeCtx("python.org"))
    assert isinstance(findings, list)
    for f in findings:
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert f["category"] == "dns"
