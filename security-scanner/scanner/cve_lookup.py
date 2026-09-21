"""Correlates detected software/version banners against the NVD (National
Vulnerability Database) public API - the same public, official data source
real vulnerability-management tools use for CVE matching.

Best-effort and network-tolerant: if NVD is unreachable, rate-limited, or the
response shape doesn't match, this simply returns no findings rather than
failing the whole scan. Set NVD_API_KEY in the environment for a much higher
rate limit (optional; works fine without one at low volume).
"""

import os
import re

import requests

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BANNER_PATTERN = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]*)/(\d+(?:\.\d+){0,3})")
MAX_RESULTS_PER_PRODUCT = 5


def _extract_banners(headers_lower):
    banners = []
    for header in ("server", "x-powered-by"):
        value = headers_lower.get(header)
        if not value:
            continue
        for match in BANNER_PATTERN.finditer(value):
            product, version = match.group(1), match.group(2)
            if product.lower() in {"apache", "nginx", "iis", "openresty"} and version.count(".") == 0:
                continue  # too vague (e.g. a bare major version) to search usefully
            banners.append((product, version))
    return banners


def _query_nvd(product, version, timeout):
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": MAX_RESULTS_PER_PRODUCT}
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    resp = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def check(ctx):
    findings = []
    resp = ctx.homepage_response
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    banners = _extract_banners(headers_lower)
    ctx.meta["detected_software"] = [f"{p}/{v}" for p, v in banners]

    for product, version in banners[:3]:  # keep the scan fast - a handful of lookups at most
        try:
            data = _query_nvd(product, version, ctx.timeout)
        except Exception:
            continue

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            continue

        cve_refs = []
        for item in vulnerabilities[:MAX_RESULTS_PER_PRODUCT]:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break
            cve_refs.append({
                "id": cve_id,
                "cvss": cvss,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        if not cve_refs:
            continue

        max_cvss = max((c["cvss"] for c in cve_refs if c["cvss"] is not None), default=None)
        severity = "info"
        if max_cvss is not None:
            if max_cvss >= 9:
                severity = "critical"
            elif max_cvss >= 7:
                severity = "high"
            elif max_cvss >= 4:
                severity = "medium"
            else:
                severity = "low"

        findings.append({
            "category": "cve",
            "title": f"Publicly known vulnerabilities may affect {product} {version}",
            "severity": severity,
            "description": (
                f"The detected banner '{product}/{version}' string-matched "
                f"{len(cve_refs)} entries in the NVD. This is a keyword match "
                "on the version string, not a confirmed exploit - the banner "
                "itself can be wrong or outdated, so verify the real installed "
                "version before acting."
            ),
            "evidence": f"Server/X-Powered-By banner: {product}/{version}",
            "recommendation": f"Confirm the actual running version of {product} and upgrade if it matches any CVE below.",
            "cve_refs": cve_refs,
        })

    return findings
