"""Turns a subset of findings into a ready-to-paste code/config snippet for
the detected backend framework. This is the "one-click remediation" idea
from the brainstorm docs, done for real: static, well-known configuration
fixes for well-known missing-header findings - not code generation via an
LLM (which could hallucinate an insecure snippet), just a small lookup table
written by hand.
"""

HEADER_SNIPPETS = {
    "Flask": (
        "# pip install flask-talisman\n"
        "from flask_talisman import Talisman\n\n"
        "Talisman(\n"
        "    app,\n"
        "    content_security_policy={'default-src': \"'self'\"},\n"
        "    force_https=True,\n"
        "    strict_transport_security=True,\n"
        "    session_cookie_secure=True,\n"
        "    session_cookie_http_only=True,\n"
        ")\n"
    ),
    "Express": (
        "// npm install helmet\n"
        "const helmet = require('helmet');\n"
        "app.use(helmet());\n"
        "app.use(helmet.contentSecurityPolicy({\n"
        "  directives: { defaultSrc: [\"'self'\"] }\n"
        "}));\n"
    ),
    "Nginx": (
        "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;\n"
        "add_header X-Content-Type-Options \"nosniff\" always;\n"
        "add_header X-Frame-Options \"DENY\" always;\n"
        "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
        "add_header Content-Security-Policy \"default-src 'self'\" always;\n"
    ),
    "Apache": (
        "Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains\"\n"
        "Header always set X-Content-Type-Options \"nosniff\"\n"
        "Header always set X-Frame-Options \"DENY\"\n"
        "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
        "Header always set Content-Security-Policy \"default-src 'self'\"\n"
    ),
    "Django": (
        "# settings.py\n"
        "SECURE_HSTS_SECONDS = 63072000\n"
        "SECURE_HSTS_INCLUDE_SUBDOMAINS = True\n"
        "SECURE_CONTENT_TYPE_NOSNIFF = True\n"
        "X_FRAME_OPTIONS = 'DENY'\n"
        "SESSION_COOKIE_SECURE = True\n"
        "SESSION_COOKIE_HTTPONLY = True\n"
        "CSRF_COOKIE_SECURE = True\n"
    ),
}

HEADER_FINDING_TITLES = {
    "Missing Strict-Transport-Security (HSTS) header",
    "Missing Content-Security-Policy (CSP) header",
    "Missing X-Content-Type-Options header",
    "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
}


def detect_framework(headers_lower):
    server = (headers_lower.get("server") or "").lower()
    powered_by = (headers_lower.get("x-powered-by") or "").lower()

    if "gunicorn" in server or "werkzeug" in server or "flask" in powered_by:
        return "Flask"
    if "express" in powered_by:
        return "Express"
    if "nginx" in server:
        return "Nginx"
    if "apache" in server:
        return "Apache"
    if "django" in powered_by or "wsgiserver" in server:
        return "Django"
    return None


def apply(findings, ctx):
    resp = ctx.homepage_response
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    framework = detect_framework(headers_lower)
    ctx.meta["detected_framework"] = framework

    if not framework or framework not in HEADER_SNIPPETS:
        return findings

    header_findings_present = any(f["title"] in HEADER_FINDING_TITLES for f in findings)
    if not header_findings_present:
        return findings

    for f in findings:
        if f["title"] in HEADER_FINDING_TITLES:
            f["code_snippet"] = HEADER_SNIPPETS[framework]
            f["code_snippet_label"] = f"Suggested fix for {framework}"

    return findings
