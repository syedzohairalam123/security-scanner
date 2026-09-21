import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urlunsplit

import requests

from scanner import (
    http_headers,
    ssl_check,
    port_scan,
    misconfig,
    token_entropy,
    access_control,
    active_probes,
    cve_lookup,
    dns_security,
    ct_monitor,
    frontend_deps,
    remediation,
    correlation,
    risk_score,
)

# Order controls the sequence findings appear in when severities tie.
CHECK_MODULES = [
    http_headers,
    ssl_check,
    misconfig,
    token_entropy,
    access_control,
    port_scan,
    cve_lookup,
    dns_security,
    ct_monitor,
    frontend_deps,
    active_probes,  # runs last: only fires anything if consent was given
]

MODULE_LABELS = {
    "scanner.http_headers": "HTTP security headers",
    "scanner.ssl_check": "TLS/SSL configuration",
    "scanner.misconfig": "Common misconfigurations",
    "scanner.token_entropy": "Session token randomness",
    "scanner.access_control": "Access control surface",
    "scanner.port_scan": "Open ports",
    "scanner.cve_lookup": "Known CVEs (NVD)",
    "scanner.dns_security": "DNS security & takeover risk",
    "scanner.ct_monitor": "Certificate Transparency logs",
    "scanner.frontend_deps": "Frontend supply chain",
    "scanner.active_probes": "Active input-validation probes",
}

USER_AGENT = "EduSecScanner/1.0 (+authorized-security-testing; see README)"


class ScanContext:
    """Shared state passed into every check module."""

    def __init__(self, target_url, allow_active_probes, config):
        parsed = urlsplit(target_url)
        self.url = target_url
        self.scheme = parsed.scheme
        self.hostname = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.base_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

        self.timeout = config.HTTP_TIMEOUT_SECONDS
        self.port_scan_timeout = config.PORT_SCAN_TIMEOUT_SECONDS
        self.port_scan_max_workers = config.PORT_SCAN_MAX_WORKERS
        self.max_timing_delay = config.MAX_TIMING_PROBE_DELAY
        self.allow_active_probes = allow_active_probes

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

        self.homepage_response = None
        self.meta = {}

    @property
    def looks_like_sensitive_page(self):
        path = urlsplit(self.url).path.lower()
        return any(k in path for k in ("account", "profile", "dashboard", "admin", "settings", "billing"))

    def fetch_homepage(self):
        try:
            self.homepage_response = self.session.get(
                self.url, timeout=self.timeout, allow_redirects=True
            )
            final = urlsplit(self.homepage_response.url)
            self.scheme = final.scheme
            self.hostname = final.hostname
            self.port = final.port or (443 if final.scheme == "https" else 80)
            self.base_url = urlunsplit((final.scheme, final.netloc, "", "", ""))
        except requests.RequestException as e:
            self.meta["fetch_error"] = str(e)


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Target URL is required.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlsplit(raw_url)
    if not parsed.hostname:
        raise ValueError("Could not parse a hostname from that URL.")
    return raw_url


def run_scan_streaming(target_url: str, allow_active_probes: bool, config):
    """Generator that yields progress events while the scan runs, then a
    final `{'type': 'done', 'result': {...}}` event. Powers the live-progress
    UI over Server-Sent Events. Never raises for target-side problems
    (unreachable host, TLS failure, etc.) - those become an 'info'/
    'connectivity' finding instead so the caller always gets a usable report;
    it can still raise ValueError for a genuinely unusable input URL.
    """
    started = time.monotonic()
    target_url = normalize_url(target_url)
    ctx = ScanContext(target_url, allow_active_probes, config)
    total_steps = len(CHECK_MODULES) + 2  # +1 connect, +1 correlation pass

    yield {"type": "progress", "message": f"Connecting to {ctx.hostname}...", "done": 0, "total": total_steps}
    ctx.fetch_homepage()

    findings = []
    errors = []

    if ctx.meta.get("fetch_error") and ctx.homepage_response is None:
        # Even if the homepage GET failed outright, still attempt TLS/port
        # checks - a lot of misconfigurations show up precisely when the app
        # itself is down but the host is still reachable.
        findings.append({
            "category": "connectivity",
            "title": "Homepage request failed",
            "severity": "info",
            "description": "The scanner could not fetch the target URL directly; some checks that depend on the page content were skipped.",
            "evidence": ctx.meta["fetch_error"],
            "recommendation": "Confirm the URL is correct and the server responds to a plain GET request.",
        })

    completed = 1
    yield {"type": "progress", "message": "Connected. Running checks...", "done": completed, "total": total_steps}

    with ThreadPoolExecutor(max_workers=len(CHECK_MODULES)) as pool:
        future_to_module = {pool.submit(module.check, ctx): module for module in CHECK_MODULES}
        for future in as_completed(future_to_module):
            module = future_to_module[future]
            label = MODULE_LABELS.get(module.__name__, module.__name__)
            completed += 1
            try:
                new_findings = future.result()
                findings.extend(new_findings)
                yield {
                    "type": "progress",
                    "message": f"{label}: {len(new_findings)} finding(s)",
                    "done": completed, "total": total_steps,
                }
            except Exception as e:  # a single check failing should never sink the whole scan
                errors.append(f"{module.__name__} raised {type(e).__name__}: {e}")
                yield {"type": "progress", "message": f"{label}: check failed, skipped", "done": completed, "total": total_steps}

    findings = remediation.apply(findings, ctx)

    chain_findings = correlation.correlate(findings)
    findings.extend(chain_findings)
    completed += 1
    yield {
        "type": "progress",
        "message": f"Correlating findings: {len(chain_findings)} finding(s)",
        "done": completed, "total": total_steps,
    }

    score, level = risk_score.compute(findings)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 4))

    duration_ms = int((time.monotonic() - started) * 1000)

    result = {
        "target_url": target_url,
        "findings": findings,
        "risk_score": score,
        "risk_level": level,
        "meta": ctx.meta,
        "errors": errors,
        "duration_ms": duration_ms,
    }
    yield {"type": "done", "result": result}


def run_scan(target_url: str, allow_active_probes: bool, config) -> dict:
    """Synchronous convenience wrapper around run_scan_streaming for callers
    that don't need live progress (e.g. the scheduled-scan cron job)."""
    result = None
    for event in run_scan_streaming(target_url, allow_active_probes, config):
        if event["type"] == "done":
            result = event["result"]
    return result
