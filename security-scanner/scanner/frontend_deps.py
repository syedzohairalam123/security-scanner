"""Front-end supply-chain checks.

Extends CVE correlation (which reads the Server header) down to the
client-side dependencies actually shipped to every visitor's browser -
often the more exploitable half of a modern stack, and something most
lightweight scanners skip entirely because it means parsing the page
instead of just its headers.

Two checks:
  1. Third-party <script> tags loaded without Subresource Integrity (SRI) -
     if that CDN/host is ever compromised, every visitor silently runs
     whatever code is served in the script's place.
  2. Script filenames matching known old/vulnerable library version
     patterns (a representative, not exhaustive, curated set).
"""

import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

KNOWN_VULNERABLE_PATTERNS = [
    (re.compile(r"jquery[.-]1\.(?:[0-9]|1[01])(?:\.\d+)?\b", re.I),
     "jQuery 1.0-1.11", "Multiple cross-site scripting issues (e.g. CVE-2020-11022, CVE-2020-11023) fixed in 1.12/3.5+."),
    (re.compile(r"jquery[.-]2\.[0-2](?:\.\d+)?\b", re.I),
     "jQuery 2.0-2.2", "Same class of jQuery.html()/.append() XSS issues as the 1.x line, fixed in 3.5+."),
    (re.compile(r"angular(?:\.min)?[.-]1\.[0-5](?:\.\d+)?\b", re.I),
     "AngularJS 1.0-1.5", "Multiple sandbox-bypass XSS issues in early AngularJS 1.x; the whole 1.x line is end-of-life."),
    (re.compile(r"bootstrap[.-]3\.[0-3](?:\.\d+)?\b", re.I),
     "Bootstrap 3.0-3.3", "XSS via tooltip/popover/affix/scrollspy data attributes (CVE-2018-14040/41/42), fixed in 3.4+."),
    (re.compile(r"lodash[.-][23]\.\d+(?:\.\d+)?\b", re.I),
     "Lodash 2.x/3.x", "Prototype-pollution issues (e.g. CVE-2019-10744), fixed in 4.17.12+."),
    (re.compile(r"moment[.-]2\.(?:[0-9]|1[0-9])\.\d+\b", re.I),
     "Moment.js < 2.20", "ReDoS issue (CVE-2017-18214) in older 2.x releases."),
    (re.compile(r"handlebars[.-][123]\.\d", re.I),
     "Handlebars 1.x-3.x", "Multiple prototype-pollution / template-injection issues fixed in 4.x."),
]


def check(ctx):
    findings = []
    resp = ctx.homepage_response
    if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
        return findings

    soup = BeautifulSoup(resp.text, "html.parser")
    target_netloc = urlsplit(ctx.url).netloc

    missing_sri = []
    outdated_libs = []
    seen_labels = set()

    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        parsed = urlsplit(src)
        is_cross_origin = bool(parsed.netloc) and parsed.netloc != target_netloc

        if is_cross_origin and not tag.has_attr("integrity"):
            missing_sri.append(src)

        for pattern, label, detail in KNOWN_VULNERABLE_PATTERNS:
            if pattern.search(src) and label not in seen_labels:
                outdated_libs.append((src, label, detail))
                seen_labels.add(label)
                break

    if missing_sri:
        sample = missing_sri[:5]
        remainder = len(missing_sri) - len(sample)
        findings.append({
            "category": "frontend_supply_chain",
            "title": f"{len(missing_sri)} third-party script(s) loaded without Subresource Integrity",
            "severity": "medium",
            "description": (
                "Subresource Integrity (SRI) lets the browser verify a "
                "fetched script's hash before executing it. Without it, if "
                "the third-party host or CDN is ever compromised or "
                "misconfigured, every visitor silently runs whatever code "
                "ends up served in its place."
            ),
            "evidence": "\n".join(sample) + (f"\n(+{remainder} more)" if remainder > 0 else ""),
            "recommendation": 'Add integrity + crossorigin attributes, e.g. <script src="..." integrity="sha384-..." crossorigin="anonymous">. Most CDNs (cdnjs, jsDelivr) publish the correct hash alongside the URL.',
        })

    for src, label, detail in outdated_libs:
        findings.append({
            "category": "frontend_supply_chain",
            "title": f"Outdated JS library detected: {label}",
            "severity": "medium",
            "description": detail,
            "evidence": f"Script src matched a known version pattern: {src}",
            "recommendation": f"Upgrade {label.split()[0]} to a current, supported release.",
        })

    return findings
