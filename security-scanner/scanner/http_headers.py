"""Checks the presence and quality of standard HTTP security headers.

This mirrors the checks a manual reviewer (or a tool like Mozilla Observatory)
performs by reading response headers - no requests beyond the ones needed to
render the page are made.
"""

SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "severity": "high",
        "description": (
            "Without HSTS, a browser that has never visited the site will still "
            "try plain HTTP first, giving a network attacker a window to "
            "intercept or downgrade the connection before the redirect to HTTPS."
        ),
        "recommendation": (
            "Once the site is served over HTTPS everywhere, add: "
            "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
        ),
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy (CSP) header",
        "severity": "high",
        "description": (
            "With no CSP, the browser has no allow-list for where scripts, styles, "
            "or frames may load from, so a successful injection (XSS) has an "
            "unrestricted blast radius."
        ),
        "recommendation": (
            "Start narrow, e.g. Content-Security-Policy: default-src 'self'; "
            "object-src 'none'; then widen only for origins you actually use."
        ),
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": "medium",
        "description": (
            "Without 'nosniff', some browsers will try to guess ('sniff') a "
            "response's MIME type, which has historically enabled content to be "
            "executed against the server's declared Content-Type."
        ),
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "title": "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
        "severity": "medium",
        "description": (
            "Nothing stops the page from being loaded inside a hidden iframe on "
            "an attacker's site, which enables clickjacking attacks."
        ),
        "recommendation": (
            "Add X-Frame-Options: DENY, or a CSP 'frame-ancestors' directive for "
            "finer-grained control."
        ),
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "severity": "low",
        "description": (
            "Without a Referrer-Policy, full URLs (which can contain tokens or "
            "identifiers in the query string) may be sent to third-party sites "
            "via the Referer header on outbound links."
        ),
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy header",
        "severity": "low",
        "description": (
            "The page does not explicitly disable powerful browser features "
            "(camera, microphone, geolocation, etc.), so any embedded or "
            "compromised third-party script inherits the default, more "
            "permissive behavior."
        ),
        "recommendation": (
            "Add a Permissions-Policy header disabling anything unused, e.g. "
            "Permissions-Policy: geolocation=(), camera=(), microphone=()"
        ),
    },
}


def check(ctx):
    findings = []
    resp = ctx.homepage_response
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name not in headers_lower:
            findings.append({
                "category": "http_headers",
                "title": meta["title"],
                "severity": meta["severity"],
                "description": meta["description"],
                "evidence": f"No '{header_name}' header on the response from {ctx.url}",
                "recommendation": meta["recommendation"],
            })

    server = headers_lower.get("server")
    if server and any(c.isdigit() for c in server):
        findings.append({
            "category": "http_headers",
            "title": "Server header discloses software/version",
            "severity": "low",
            "description": (
                "The Server header names specific software and a version number, "
                "which lets an attacker shortlist known CVEs for that exact build "
                "without any guesswork."
            ),
            "evidence": f"Server: {server}",
            "recommendation": (
                "Suppress or generalize the header, e.g. 'ServerTokens Prod' on "
                "Apache or 'server_tokens off;' on Nginx."
            ),
        })

    powered_by = headers_lower.get("x-powered-by")
    if powered_by:
        findings.append({
            "category": "http_headers",
            "title": "X-Powered-By header discloses backend framework",
            "severity": "low",
            "description": "This header exists purely as a fingerprinting aid for attackers; it has no functional purpose for real users.",
            "evidence": f"X-Powered-By: {powered_by}",
            "recommendation": "Disable it in your framework config (e.g. app.disable('x-powered-by') in Express).",
        })

    cache_control = headers_lower.get("cache-control", "")
    if ctx.looks_like_sensitive_page and "no-store" not in cache_control:
        findings.append({
            "category": "http_headers",
            "title": "Sensitive-looking page may be cacheable",
            "severity": "low",
            "description": (
                "The page URL/content suggests it may show account or session-"
                "specific data, but the Cache-Control header does not include "
                "'no-store', so shared caches or the browser disk cache could "
                "retain a copy."
            ),
            "evidence": f"Cache-Control: {cache_control or '(not set)'}",
            "recommendation": "Add 'Cache-Control: no-store' to any response containing personal or session data.",
        })

    return findings
