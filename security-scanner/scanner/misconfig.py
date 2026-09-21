"""Common security misconfiguration checks.

Covers: cookie flags, CORS, exposed version-control/config files, directory
listing, and verbose error/stack-trace disclosure. Every request here is a
plain GET to a handful of well-known, publicly documented paths - the same
checks a manual reviewer would run by hand.
"""

EXPOSED_PATH_CHECKS = [
    (".git/config", "critical", "Exposed .git directory can leak full source history, including past secrets."),
    (".env", "critical", "Exposed .env file commonly contains database credentials and API keys in plain text."),
    ("wp-config.php.bak", "critical", "A WordPress config backup can expose database credentials."),
    ("config.php.bak", "high", "A backup of a config file may expose credentials or internal details."),
    (".DS_Store", "low", "A .DS_Store file can leak the names of other files/folders on the server."),
    ("phpinfo.php", "high", "phpinfo() output discloses detailed server/software configuration to any visitor."),
    (".well-known/security.txt", "info", "security.txt tells researchers how to responsibly report vulnerabilities."),
]

ERROR_SIGNATURES = [
    "Traceback (most recent call last)",
    "Warning: mysqli",
    "ORA-01756",
    "Microsoft OLE DB Provider for ODBC Drivers",
    "unhandled exception",
    "at System.",
    "Fatal error:",
    "Whoops, looks like something went wrong",
]

DIRECTORY_LISTING_MARKERS = ["Index of /", "<title>Directory listing for"]


def _check_cookies(ctx, resp):
    findings = []
    try:
        raw_cookies = resp.raw.headers.get_all("Set-Cookie") or []
    except AttributeError:
        single = resp.headers.get("Set-Cookie")
        raw_cookies = [single] if single else []

    for raw in raw_cookies:
        lowered = raw.lower()
        name = raw.split("=", 1)[0].strip()
        looks_like_session = any(k in name.lower() for k in ("session", "sid", "auth", "token"))
        missing = []
        if "secure" not in lowered and ctx.scheme == "https":
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append({
                "category": "misconfig",
                "title": f"Cookie '{name}' missing {'/'.join(missing)} flag(s)",
                "severity": "high" if looks_like_session and "HttpOnly" in missing else "medium",
                "description": (
                    "Cookies without HttpOnly are readable by JavaScript (and thus "
                    "by an XSS payload); without Secure they can be sent over "
                    "plain HTTP; without SameSite they are attached to "
                    "cross-site requests, enabling CSRF."
                ),
                "evidence": raw.split(";")[0] + " ; missing: " + ", ".join(missing),
                "recommendation": "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on every session/auth cookie.",
            })
    return findings


def _check_cors(headers_lower):
    findings = []
    acao = headers_lower.get("access-control-allow-origin")
    acac = headers_lower.get("access-control-allow-credentials")
    if acao == "*" and acac == "true":
        findings.append({
            "category": "misconfig",
            "title": "CORS allows any origin together with credentials",
            "severity": "critical",
            "description": (
                "Access-Control-Allow-Origin: * combined with "
                "Access-Control-Allow-Credentials: true lets any website read "
                "authenticated responses on behalf of a logged-in visitor. "
                "Browsers only permit this combination because most servers "
                "misconfigure it - it should never be paired like this."
            ),
            "evidence": "Access-Control-Allow-Origin: * ; Access-Control-Allow-Credentials: true",
            "recommendation": "Echo back a specific, validated Origin instead of '*' whenever credentials are allowed.",
        })
    elif acao == "*":
        findings.append({
            "category": "misconfig",
            "title": "CORS allows any origin",
            "severity": "low",
            "description": "Any website can read this endpoint's response via fetch/XHR. Fine for public data, risky for anything user-specific.",
            "evidence": "Access-Control-Allow-Origin: *",
            "recommendation": "Restrict to the specific origins that legitimately need access, unless the endpoint is intentionally public.",
        })
    return findings


def check(ctx):
    findings = []
    resp = ctx.homepage_response
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:20000] if resp.text else ""

    findings.extend(_check_cookies(ctx, resp))
    findings.extend(_check_cors(headers_lower))

    if any(marker in body for marker in DIRECTORY_LISTING_MARKERS):
        findings.append({
            "category": "misconfig",
            "title": "Directory listing appears to be enabled",
            "severity": "medium",
            "description": "The server returned a browsable file index instead of a normal page, exposing the raw contents of a directory.",
            "evidence": f"Response body matched a directory-index pattern for {ctx.url}",
            "recommendation": "Disable autoindex/directory browsing in your web server config for any publicly reachable path.",
        })

    for signature in ERROR_SIGNATURES:
        if signature.lower() in body.lower():
            findings.append({
                "category": "misconfig",
                "title": "Verbose error output detected",
                "severity": "medium",
                "description": "The homepage response includes what looks like a stack trace or framework debug page, which can reveal file paths, library versions, or query fragments.",
                "evidence": f"Matched signature: '{signature}'",
                "recommendation": "Disable debug mode in production and show a generic error page instead.",
            })
            break  # one instance is enough signal, avoid duplicate findings

    for path, severity, description in EXPOSED_PATH_CHECKS:
        url = ctx.base_url.rstrip("/") + "/" + path
        try:
            r = ctx.session.get(url, timeout=ctx.timeout, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            findings.append({
                "category": "misconfig",
                "title": f"Publicly accessible: /{path}",
                "severity": severity,
                "description": description,
                "evidence": f"GET {url} -> HTTP {r.status_code}",
                "recommendation": f"Remove or block public access to /{path}; it should never be served to visitors.",
            })

    return findings
