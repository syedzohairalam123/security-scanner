"""Checks for commonly-exposed admin/management surfaces.

This performs plain GET requests against well-known administrative paths to
see whether they are reachable without authentication - the same first step
any manual reviewer or automated scanner (Nikto, etc.) takes. It never
attempts to log in, guess credentials, or interact with anything beyond
observing the HTTP status/response of these read-only requests.
"""

SENSITIVE_PATHS = [
    ("admin/", "Admin panel", "high"),
    ("wp-admin/", "WordPress admin", "medium"),
    ("phpmyadmin/", "phpMyAdmin", "critical"),
    ("server-status", "Apache server-status", "high"),
    ("actuator/health", "Spring Boot Actuator", "medium"),
    ("actuator/env", "Spring Boot Actuator (env - can leak secrets)", "critical"),
    (".well-known/", "Well-known metadata directory", "info"),
    ("api/swagger.json", "Exposed API schema (Swagger/OpenAPI)", "low"),
    ("graphql", "GraphQL endpoint", "info"),
]

DEFAULT_INSTALL_MARKERS = {
    "It works!": "Default Apache/Nginx placeholder page still live",
    "Welcome to nginx!": "Default Nginx placeholder page still live",
    "iisstart.htm": "Default IIS placeholder page still live",
}


def check(ctx):
    findings = []

    for path, label, severity in SENSITIVE_PATHS:
        url = ctx.base_url.rstrip("/") + "/" + path
        try:
            r = ctx.session.get(url, timeout=ctx.timeout, allow_redirects=True)
        except Exception:
            continue

        if r.status_code == 200:
            findings.append({
                "category": "access_control",
                "title": f"{label} reachable without authentication",
                "severity": severity,
                "description": (
                    f"'{path}' returned HTTP 200 with no login prompt, so this "
                    "surface is exposed to anyone on the internet."
                ),
                "evidence": f"GET {url} -> HTTP {r.status_code}",
                "recommendation": "Require authentication for this path, restrict it to an internal network/VPN, or remove it if unused.",
            })

    resp = ctx.homepage_response
    if resp is not None and resp.text:
        for marker, message in DEFAULT_INSTALL_MARKERS.items():
            if marker in resp.text:
                findings.append({
                    "category": "access_control",
                    "title": message,
                    "severity": "medium",
                    "description": "The homepage still shows the web server's default placeholder rather than the real application, usually meaning deployment is incomplete or misrouted.",
                    "evidence": f"Homepage body contains '{marker}'",
                    "recommendation": "Replace the default page with the real application, or confirm routing/virtual-host configuration is correct.",
                })

    return findings
