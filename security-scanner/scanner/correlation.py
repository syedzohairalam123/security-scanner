"""Finding correlation ("attack-chain") engine.

A flat list of findings understates risk when several individually
low/medium issues combine into something categorically worse - a standard
idea in mature vulnerability management (attack-path / kill-chain
analysis), applied here as a small, explicit, auditable rule set over
findings this scan already produced.

This module makes no network requests and runs no new checks against the
target - it only reads and re-combines what the other modules already
found, and every rule below names the exact constituent findings it fired
on so the reasoning is checkable, not a black box.
"""


def _first(findings, *, category=None, title_contains=None):
    for f in findings:
        if category and f.get("category") != category:
            continue
        if title_contains and title_contains.lower() not in f.get("title", "").lower():
            continue
        return f
    return None


def _cookie_missing_httponly(findings):
    for f in findings:
        if "cookie" in f.get("title", "").lower() and "HttpOnly" in (f.get("evidence") or ""):
            return f
    return None


def correlate(findings):
    chains = []

    xss = _first(findings, category="active_probe", title_contains="xss")
    no_csp = _first(findings, title_contains="content-security-policy")
    weak_cookie = _cookie_missing_httponly(findings)

    if xss and no_csp:
        constituents = [xss, no_csp] + ([weak_cookie] if weak_cookie else [])
        narrative = (
            "Reflected input isn't HTML-escaped, and there's no "
            "Content-Security-Policy to contain what an injected <script> "
            "is allowed to do once it runs."
        )
        if weak_cookie:
            narrative += (
                " On top of that, the session cookie is readable by "
                "JavaScript (no HttpOnly), so the same injection can read "
                "and exfiltrate it directly - a complete path from one "
                "unescaped parameter to a stolen session."
            )
        chains.append({
            "category": "attack_chain",
            "title": "Chain: reflected XSS \u2192 full session compromise" if weak_cookie else "Chain: reflected XSS has an unrestricted blast radius",
            "severity": "critical" if weak_cookie else "high",
            "description": narrative,
            "evidence": " + ".join(f["title"] for f in constituents),
            "recommendation": "Fixing any single link breaks the chain, but fix all of them: escape output, add a CSP, and set HttpOnly (plus Secure and SameSite) on session cookies.",
        })

    exposed_admin = _first(findings, category="access_control", title_contains="reachable without authentication")
    guessable_session = _first(findings, category="token_entropy", title_contains="sequential")
    if exposed_admin and guessable_session:
        chains.append({
            "category": "attack_chain",
            "title": "Chain: guessable session IDs reach an exposed admin surface",
            "severity": "critical",
            "description": (
                "An administrative path is reachable without its own "
                "authentication check, and session identifiers look "
                "sequential or otherwise predictable rather than "
                "cryptographically random. Combined, an attacker doesn't "
                "need to steal a specific session - they can iterate "
                "plausible IDs until one lands on an authenticated session, "
                "then walk straight into the admin surface."
            ),
            "evidence": f"{exposed_admin['title']} + {guessable_session['title']}",
            "recommendation": "Put a real authentication/authorization check in front of the admin surface regardless, and switch session IDs to a cryptographically random generator either way.",
        })

    no_https = _first(findings, title_contains="plain http")
    no_hsts = _first(findings, title_contains="hsts")
    if no_https and no_hsts:
        chains.append({
            "category": "attack_chain",
            "title": "Chain: no forced HTTPS leaves every visit open to downgrade",
            "severity": "high",
            "description": (
                "The site doesn't force HTTPS and has no HSTS header telling "
                "browsers to remember to use HTTPS next time. Every time "
                "someone types the bare domain or follows an old http:// "
                "link, a network attacker on the same Wi-Fi or router gets a "
                "window to intercept or rewrite the page before it upgrades."
            ),
            "evidence": f"{no_https['title']} + {no_hsts['title']}",
            "recommendation": "Redirect all HTTP to HTTPS at the server/load balancer, then add Strict-Transport-Security so browsers stop attempting HTTP for this host entirely.",
        })

    sqli = _first(findings, category="active_probe", title_contains="sql injection")
    verbose_errors = _first(findings, title_contains="verbose error")
    if sqli and verbose_errors:
        chains.append({
            "category": "attack_chain",
            "title": "Chain: SQL injection paired with verbose error output",
            "severity": "critical",
            "description": (
                "A SQL injection point exists, and the application also "
                "leaks stack traces or debug output on error - which "
                "typically hands an attacker the exact query, table, and "
                "column names needed to extract data quickly instead of "
                "guessing blind."
            ),
            "evidence": f"{sqli['title']} + {verbose_errors['title']}",
            "recommendation": "Fix the injection with parameterized queries, and disable debug/verbose error pages in production regardless of the injection fix.",
        })

    takeover = _first(findings, category="dns", title_contains="takeover")
    weak_spf = _first(findings, title_contains="+all") or _first(findings, title_contains="no spf")
    if takeover and weak_spf:
        chains.append({
            "category": "attack_chain",
            "title": "Chain: subdomain takeover risk compounded by weak email authentication",
            "severity": "critical",
            "description": (
                "A dangling DNS record makes a subdomain takeover plausible, "
                "and email sender authentication (SPF) is missing or "
                "permissive. If the subdomain is re-claimed, it can likely "
                "also be used to send convincing phishing email that "
                "appears to come from this domain."
            ),
            "evidence": f"{takeover['title']} + {weak_spf['title']}",
            "recommendation": "Remove the dangling DNS record first; independently tighten SPF/DMARC so this domain can't be used to spoof mail either way.",
        })

    return chains
