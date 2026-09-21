import math
import pytest

from scanner.risk_score import compute as compute_risk
from scanner.token_entropy import shannon_entropy
from scanner.orchestrator import normalize_url
from scanner.remediation import detect_framework


class TestRiskScore:
    def test_no_findings_is_zero(self):
        score, level = compute_risk([])
        assert score == 0.0
        assert level == "info"

    def test_single_critical_pushes_level_up(self):
        score, level = compute_risk([{"severity": "critical"}])
        assert score > 0
        assert level in ("high", "critical")

    def test_more_findings_never_lowers_score(self):
        base, _ = compute_risk([{"severity": "medium"}])
        more, _ = compute_risk([{"severity": "medium"}, {"severity": "low"}])
        assert more >= base

    def test_score_stays_within_bounds(self):
        many_criticals = [{"severity": "critical"} for _ in range(50)]
        score, level = compute_risk(many_criticals)
        assert 0 <= score <= 100
        assert level == "critical"

    def test_unknown_severity_does_not_crash(self):
        score, level = compute_risk([{"severity": "made-up"}])
        assert score >= 0


class TestTokenEntropy:
    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_repeated_character_is_zero_entropy(self):
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_uniform_four_symbol_alphabet_is_two_bits(self):
        # Shannon entropy of a string using 4 equally-frequent symbols is
        # exactly log2(4) = 2.0 bits/char.
        assert math.isclose(shannon_entropy("abcdabcd"), 2.0, rel_tol=1e-9)

    def test_more_varied_string_has_higher_entropy_than_repetitive_one(self):
        low = shannon_entropy("aaaaaaaaaaaaaaaa")
        high = shannon_entropy("Xk9$mQ2!pL7@zR4#")
        assert high > low


class TestNormalizeUrl:
    def test_adds_https_scheme_when_missing(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_leaves_explicit_scheme_alone(self):
        assert normalize_url("http://example.com") == "http://example.com"

    def test_strips_surrounding_whitespace(self):
        assert normalize_url("  example.com  ") == "https://example.com"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            normalize_url("")

    def test_unparseable_input_raises(self):
        with pytest.raises(ValueError):
            normalize_url("https://")


class TestDetectFramework:
    def test_flask_from_werkzeug_server_header(self):
        assert detect_framework({"server": "Werkzeug/3.0.1 Python/3.12"}) == "Flask"

    def test_nginx(self):
        assert detect_framework({"server": "nginx/1.18.0"}) == "Nginx"

    def test_express_from_powered_by(self):
        assert detect_framework({"x-powered-by": "Express"}) == "Express"

    def test_unknown_returns_none(self):
        assert detect_framework({"server": "MysteryServer/1.0"}) is None

    def test_no_headers_returns_none(self):
        assert detect_framework({}) is None
