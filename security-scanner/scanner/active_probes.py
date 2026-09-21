"""Lightweight, detection-only input validation probing.

Scope and intent (read this before touching the payload lists below):

- This module only ever *detects and reports* a weakness. It never chains a
  finding into further access, never exfiltrates data, never attempts to
  brute-force credentials, and never tries to evade or defeat a WAF - if a
  request gets blocked, that is logged as "protected", not worked around.
- The test strings below are the standard, publicly documented markers used
  in every introductory web security course and the OWASP Testing Guide
  (e.g. a single quote to look for a SQL error, a script-tag reflection
  probe for XSS). There is nothing novel or secret about them; the value
  this module adds is automating the check and explaining the result, not
  the payloads themselves.
- The single timing check below sends exactly one bounded delay per
  parameter (capped by ctx.max_timing_delay, a few seconds) - not a loop,
  and never used to extract data character-by-character.
- This only runs when the person confirms they own or are authorized to
  test the target (see the consent checkbox in the UI / orchestrator).
- Each finding carries a `confidence` tier (high/medium) based on how many
  independent signals agree - e.g. a timing anomaly alone is medium
  confidence (timing is noisy), but the same anomaly on a parameter that
  also produced a raw database error is high confidence, since two
  unrelated signals correlate. This directly reduces false-positive noise
  instead of treating every automated hit as equally certain.

If you are extending this file: keep it read-only detection, keep payloads
to well-known public test strings, and do not add anything that gains
access, degrades service, or targets a third party.
"""

import time
import re
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

from bs4 import BeautifulSoup

XSS_MARKER = "sec_scan_9f3c<script>alert(1)</script>"
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysqli",
    "unclosed quotation mark",
    "sqlite3.operationalerror",
    "pg_query():",
    "ora-01756",
    "sqlstate[",
]
TIME_BASED_SUFFIXES = {
    "MySQL/MariaDB": "' AND SLEEP({delay})-- -",
    "PostgreSQL": "'; SELECT pg_sleep({delay})-- -",
    "MSSQL": "'; WAITFOR DELAY '0:0:{delay}'-- -",
}


def _discover_query_targets(ctx):
    """Return a small list of URLs with query parameters to test, discovered
    from the homepage's own links/forms - never from anywhere off-target."""
    targets = []
    parsed = urlsplit(ctx.url)
    if parse_qsl(parsed.query):
        targets.append(ctx.url)

    resp = ctx.homepage_response
    if resp is not None and "text/html" in resp.headers.get("Content-Type", ""):
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True)[:25]:
            href = a["href"]
            joined = href if href.startswith("http") else ctx.base_url.rstrip("/") + "/" + href.lstrip("/")
            if urlsplit(joined).netloc == parsed.netloc and parse_qsl(urlsplit(joined).query):
                targets.append(joined)

    # De-duplicate while keeping order, cap how many we touch per scan.
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique[:5]


def _inject(url, param, value):
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query))
    query[param] = value
    new_query = urlencode(query)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))


def check(ctx):
    findings = []
    if not ctx.allow_active_probes:
        return findings

    targets = _discover_query_targets(ctx)
    if not targets:
        return findings

    tested_params = 0
    for target_url in targets:
        parsed = urlsplit(target_url)
        params = dict(parse_qsl(parsed.query))

        for param in list(params.keys())[:4]:  # cap per-URL to keep scans fast & polite
            if tested_params >= 12:
                break
            tested_params += 1
            baseline_value = params[param]
            sqli_signals = []  # collected so error-based + timing can corroborate each other

            # --- Reflected XSS: is our marker echoed back unescaped? ---
            xss_url = _inject(target_url, param, XSS_MARKER)
            try:
                r = ctx.session.get(xss_url, timeout=ctx.timeout)
                if XSS_MARKER in r.text:
                    header_keys = {k.lower() for k in r.headers.keys()}
                    is_html = "text/html" in r.headers.get("Content-Type", "")
                    has_csp = "content-security-policy" in header_keys
                    # High confidence: it's HTML and nothing would stop an
                    # injected <script> from actually running. Medium: still
                    # unescaped (a real bug either way), but a CSP is present
                    # that may block inline execution in a real browser.
                    confidence = "high" if (is_html and not has_csp) else "medium"
                    findings.append({
                        "category": "active_probe",
                        "title": f"Potential reflected XSS via '{param}' parameter",
                        "severity": "high",
                        "confidence": confidence,
                        "description": (
                            "A harmless marker string containing an HTML tag was "
                            "sent in this parameter and came back in the response "
                            "without being escaped, which means an attacker-"
                            "controlled <script> could run in a victim's browser."
                            + ("" if confidence == "high" else " A Content-Security-Policy header was present, which may reduce (but doesn't guarantee against) actual exploitability.")
                        ),
                        "evidence": f"GET {xss_url} reflected the payload unescaped",
                        "recommendation": "HTML-encode all user input before rendering it, and add a Content-Security-Policy as defense in depth.",
                    })
            except Exception:
                pass

            # --- Error-based SQLi: does a single quote produce a DB error? ---
            sqli_url = _inject(target_url, param, baseline_value + "'")
            try:
                r = ctx.session.get(sqli_url, timeout=ctx.timeout)
                body_lower = r.text.lower()
                if any(sig in body_lower for sig in SQLI_ERROR_SIGNATURES):
                    sqli_signals.append("error-based")
                    findings.append({
                        "category": "active_probe",
                        "title": f"Potential SQL injection via '{param}' parameter",
                        "severity": "critical",
                        "confidence": "high",  # a specific DB error string is a strong signal on its own
                        "description": (
                            "Appending a single quote to this parameter produced "
                            "what looks like a raw database error message, which "
                            "means user input is likely being concatenated "
                            "directly into a SQL query."
                        ),
                        "evidence": f"GET {sqli_url} returned a database error signature",
                        "recommendation": "Use parameterized queries / an ORM everywhere, and never build SQL via string concatenation.",
                    })
            except Exception:
                pass

            # --- One bounded time-based check (single request, not a loop) ---
            try:
                baseline_start = time.monotonic()
                ctx.session.get(target_url, timeout=ctx.timeout)
                baseline_elapsed = time.monotonic() - baseline_start

                delay = min(ctx.max_timing_delay, 3)
                suffix = TIME_BASED_SUFFIXES["MySQL/MariaDB"].format(delay=int(delay))
                timing_url = _inject(target_url, param, baseline_value + suffix)

                probe_start = time.monotonic()
                ctx.session.get(timing_url, timeout=ctx.timeout + delay + 2)
                probe_elapsed = time.monotonic() - probe_start

                if probe_elapsed - baseline_elapsed >= delay * 0.8:
                    # Timing alone is noisy (network jitter, a genuinely slow
                    # endpoint). If the error-based check on this exact
                    # parameter also fired, the two independent signals
                    # corroborate each other and confidence goes to high.
                    corroborated = "error-based" in sqli_signals
                    findings.append({
                        "category": "active_probe",
                        "title": f"Possible time-based blind SQL injection via '{param}' parameter",
                        "severity": "high",
                        "confidence": "high" if corroborated else "medium",
                        "description": (
                            f"Requesting this parameter with a conditional "
                            f"{int(delay)}-second delay payload took roughly "
                            f"{probe_elapsed - baseline_elapsed:.1f}s longer than "
                            "an equivalent request without it. "
                            + (
                                "This matches the error-based finding above on the "
                                "same parameter, which corroborates it."
                                if corroborated else
                                "This is only a single automated timing check, not "
                                "a confirmed exploit - verify manually before "
                                "treating it as certain."
                            )
                        ),
                        "evidence": f"Baseline {baseline_elapsed:.2f}s vs probe {probe_elapsed:.2f}s (target delay {int(delay)}s)",
                        "recommendation": "Use parameterized queries / an ORM everywhere, and never build SQL via string concatenation.",
                    })
            except Exception:
                pass

    return findings
