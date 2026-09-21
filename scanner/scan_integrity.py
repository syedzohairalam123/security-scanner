"""Scan-integrity check: did we actually reach the real target page?

Large, high-traffic sites (Google chief among them) frequently serve a
different response to automated/non-browser-like requests than to a real
first-time visitor: a cookie/consent notice, a "before you continue" wall,
a bot-detection challenge (Cloudflare's "Just a moment...", Google's own
"unusual traffic from your computer network" page), etc. If that's what
this scan actually received, every header/cookie finding elsewhere in the
report describes the *interstitial*, not the site the person meant to
test - which would otherwise look like a normal (if noisy) result instead
of what it actually is: an unreliable scan.

This check makes that failure mode visible instead of silent. It never
tries to defeat, bypass, or work around the interstitial (no header
spoofing beyond identifying honestly, no headless-browser rendering, no
cookie injection to force through a consent wall) - it only reports when
one was likely hit, so a person reviewing the results knows to re-check.
"""

import hashlib
import re

from bs4 import BeautifulSoup

INTERSTITIAL_MARKERS = [
    "unusual traffic from your computer network",   # Google's own bot-detection page
    "before you continue to google",                # Google's consent notice
    "our systems have detected unusual traffic",
    "checking your browser before accessing",        # Cloudflare challenge
    "just a moment...",                               # Cloudflare challenge title
    "verify you are human",
    "please verify you are a human",
    "enable javascript and cookies to continue",
    "attention required! | cloudflare",
    "are you a robot",
    "to continue, please type the characters",         # Amazon-style bot check
    "pardon our interruption",
]

# A real, content-bearing homepage is essentially never this short; a
# consent/challenge page usually is.
MIN_EXPECTED_LENGTH_AFTER_REDIRECT = 1000


def _visible_text(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    for element in soup(["script", "style", "noscript"]):
        element.decompose()
    return re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip().lower()


def fingerprint_response(response):
    """Return a small, stable fingerprint for a fetched HTML response."""
    text = response.text or ""
    visible_text = _visible_text(text)
    content_length = len(getattr(response, "content", b"") or text)
    if content_length < 1000:
        length_bucket = "under-1k"
    elif content_length < 10000:
        length_bucket = "1k-10k"
    elif content_length < 100000:
        length_bucket = "10k-100k"
    else:
        length_bucket = "100k-plus"

    return {
        "title": _page_title(text),
        "content_length_bucket": length_bucket,
        "visible_text_hash": hashlib.sha256(visible_text.encode("utf-8")).hexdigest(),
        "header_names": sorted(name.lower() for name in response.headers),
    }


def compare_fingerprints(previous, current):
    """Describe a meaningful response-shape change between two scans."""
    if not previous or not current:
        return None

    changed = []
    score = 0
    if previous.get("title") != current.get("title"):
        changed.append("page title")
        score += 2
    if previous.get("content_length_bucket") != current.get("content_length_bucket"):
        changed.append("content-length bucket")
        score += 1
    if previous.get("visible_text_hash") != current.get("visible_text_hash"):
        changed.append("normalized visible text")
        score += 2
    if set(previous.get("header_names", [])) != set(current.get("header_names", [])):
        changed.append("response header names")
        score += 1

    if score < 3 and not ("page title" in changed and "normalized visible text" in changed):
        return None
    return {"changed": changed, "score": score}


def baseline_fingerprint_finding(delta):
    """Build the normal finding schema for a baseline response change."""
    changed = ", ".join(delta["changed"])
    return {
        "category": "scan_integrity",
        "title": "The response changed substantially from the previous scan",
        "severity": "high",
        "confidence": "medium",
        "description": (
            "The target returned a substantially different page shape than on "
            "the previous scan. Header and vulnerability findings may describe "
            "an interstitial, alternate origin, or another response variant "
            "rather than the same real page."
        ),
        "evidence": f"Fingerprint changed in: {changed} (delta score {delta['score']}).",
        "recommendation": (
            "Review the two responses manually and repeat the scan from the "
            "same authorized environment before treating page-level findings "
            "as a regression."
        ),
    }


def _page_title(html_text):
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip()[:120]
    except Exception:
        pass
    return None


def check(ctx):
    if getattr(ctx, "meta", {}).get("skip_scan_integrity_check"):
        return []
    resp = ctx.homepage_response
    if resp is None or not resp.text:
        return []

    body_lower = resp.text.lower()
    matched_marker = next((m for m in INTERSTITIAL_MARKERS if m in body_lower), None)

    followed_a_redirect = len(ctx.redirect_chain) > 1
    is_suspiciously_short = len(resp.text) < MIN_EXPECTED_LENGTH_AFTER_REDIRECT

    if not matched_marker and not (followed_a_redirect and is_suspiciously_short):
        return []

    title = _page_title(resp.text)
    if matched_marker:
        reason = f'page text matched a known interstitial phrase: "{matched_marker}"'
    else:
        reason = (
            f"response body is only {len(resp.text)} characters after following a "
            "redirect - unusually short for a real homepage"
        )

    evidence = reason
    if title:
        evidence += f'; page title: "{title}"'

    finding = {
        "category": "scan_integrity",
        "title": "This response may be a bot-check, consent wall, or challenge page rather than the real site",
        "severity": "high",
        "confidence": "high" if matched_marker else "medium",
        "description": (
            "The page this scan actually received looks like it might be an "
            "interstitial - a cookie/consent notice, a 'prove you're human' "
            "challenge, or similar - rather than the site's genuine homepage. "
            "Automated requests (no browser fingerprint, no prior cookies, no "
            "JavaScript execution) commonly trigger these on large sites, "
            "even with a browser-like User-Agent string. If that's what "
            "happened here, every other finding in this report describes the "
            "interstitial page, not the actual target, and should not be "
            "trusted at face value."
        ),
        "evidence": evidence,
        "recommendation": (
            "Re-run the scan later or from a different network. If this "
            "persists, the target is likely actively distinguishing "
            "automated traffic from real visitors - confirm manually in an "
            "actual browser (with no prior cookies, e.g. a private/incognito "
            "window) what a first-time visitor really sees before trusting "
            "the header findings below."
        ),
    }
    retry_note = getattr(ctx, "meta", {}).get("scan_integrity_retry_note")
    if retry_note:
        finding["evidence"] += f" {retry_note}"
    return [finding]
